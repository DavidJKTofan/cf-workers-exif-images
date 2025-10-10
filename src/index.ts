/**
 * src/index.ts
 *
 * - Multi-field EXIF insertion for JPEGs (0th IFD entries for common tags).
 * - Rejects non-JPEG main images when metadata is provided (EXIF only supported on JPEG).
 * - Preserves watermark resizing and transform behavior.
 * - No third-party packages.
 */

declare const WEB_PACKAGE_VERSION: string | undefined;
const USER_AGENT = `Cloudflare-Image-Protector/1.0 (+https://example.com)`;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

interface Env {
	IMAGES_BUCKET: R2Bucket;
}

function logInfo(...args: any[]) {
	try {
		console.log('[img-prot]', ...args);
	} catch {}
}
function logError(...args: any[]) {
	try {
		console.error('[img-prot]', ...args);
	} catch {}
}

async function hashBufferHex(buf: ArrayBuffer): Promise<string> {
	const h = await crypto.subtle.digest('SHA-256', buf);
	const bytes = new Uint8Array(h);
	let s = '';
	for (const b of bytes) s += b.toString(16).padStart(2, '0');
	return s;
}

function extFromContentType(ct: string | null): string {
	if (!ct) return 'bin';
	ct = ct.toLowerCase();
	if (ct.includes('jpeg')) return 'jpg';
	if (ct.includes('png')) return 'png';
	if (ct.includes('svg')) return 'svg';
	if (ct.includes('webp')) return 'webp';
	if (ct.includes('heic') || ct.includes('heif')) return 'heic';
	return 'bin';
}

function okJson(body: any, status = 200) {
	return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json;charset=utf-8' } });
}

function readUint32BE(u8: Uint8Array, offset: number) {
	return (u8[offset] << 24) | (u8[offset + 1] << 16) | (u8[offset + 2] << 8) | u8[offset + 3];
}

function toArrayBuffer(u: Uint8Array) {
	return u.slice().buffer;
}

/* ---------- Image dimension parsers ---------- */

function getPngDimensions(buffer: ArrayBuffer): { w: number; h: number } | null {
	const u8 = new Uint8Array(buffer);
	if (u8.length < 24) return null;
	const sig = '\x89PNG\r\n\x1a\n';
	if (decoder.decode(u8.subarray(0, 8)) !== sig) return null;
	const type = decoder.decode(u8.subarray(12, 16));
	if (type !== 'IHDR') return null;
	const width = readUint32BE(u8, 16);
	const height = readUint32BE(u8, 20);
	return { w: width, h: height };
}

function getJpegDimensions(buffer: ArrayBuffer): { w: number; h: number } | null {
	const u8 = new Uint8Array(buffer);
	if (u8.length < 4) return null;
	if (u8[0] !== 0xff || u8[1] !== 0xd8) return null;
	let offset = 2;
	while (offset < u8.length - 9) {
		if (u8[offset] !== 0xff) {
			offset++;
			continue;
		}
		const marker = u8[offset + 1];
		if (marker === 0xd8 || marker === 0xd9) {
			offset += 2;
			continue;
		}
		const len = (u8[offset + 2] << 8) | u8[offset + 3];
		if (len < 2) return null;
		if (marker === 0xc0 || marker === 0xc1 || marker === 0xc2) {
			const pos = offset + 4;
			const height = (u8[pos + 1] << 8) | u8[pos + 2];
			const width = (u8[pos + 3] << 8) | u8[pos + 4];
			return { w: width, h: height };
		}
		offset += 2 + len;
	}
	return null;
}

/* ---------- Robust external fetch helper ---------- */

async function fetchResource(urlStr: string, label: string) {
	if (!urlStr || typeof urlStr !== 'string') throw new Error(`${label}: invalid URL`);
	const trimmed = urlStr.trim();
	const attempts = [trimmed];
	try {
		new URL(trimmed);
	} catch {
		if (!/^https?:\/\//i.test(trimmed)) attempts.push('https://' + trimmed);
	}
	let lastErr: any = null;
	for (const candidate of attempts) {
		try {
			logInfo('fetchResource: trying', { label, url: candidate });
			const res = await fetch(candidate, { redirect: 'follow', headers: { 'User-Agent': USER_AGENT, Accept: 'image/*,*/*;q=0.8' } });
			if (!res.ok) {
				const txt = await res
					.clone()
					.text()
					.catch(() => '');
				const e = new Error(
					`${label} fetch failed: ${res.status} ${res.statusText} (${candidate}) ${txt ? ' snippet: ' + txt.slice(0, 200) : ''}`
				);
				logError(e);
				lastErr = e;
				continue;
			}
			const buf = await res.arrayBuffer();
			const ct = res.headers.get('content-type') || 'application/octet-stream';
			logInfo('fetchResource success', { label, url: candidate, bytes: buf.byteLength, contentType: ct });
			return { buffer: buf, contentType: ct, url: candidate };
		} catch (err) {
			lastErr = err;
			logError('fetchResource error', { candidate, err });
		}
	}
	throw lastErr instanceof Error ? lastErr : new Error(`${label} fetch failed for: ${attempts.join(',')}`);
}

/* ---------- EXIF insertion (multiple 0th IFD entries) ---------- */

/**
 * Build APP1 Exif payload with multiple ASCII entries. Returns the APP1 payload bytes (starting with "Exif\0\0").
 *
 * Supported mapped tags:
 *  - ImageDescription (0x010E) => metadata['Description']
 *  - Artist (0x013B) => metadata['Author']
 *  - Copyright (0x8298) => metadata['Copyright']
 *
 * Remaining keys are included as JSON appended to ImageDescription.
 *
 * Implements little-endian TIFF ('II') with simple 0th IFD entries containing ASCII strings.
 */
function buildExifApp1PayloadFromMetadata(metadata: Record<string, string>): Uint8Array {
	// helper to encode ASCII (we'll assume user input is representable in ASCII; non-ascii will be UTF-8 bytes - many readers accept ASCII only but some expect UTF-8; this is a simple implementation)
	function asBytes(s: string) {
		return encoder.encode(s + '\x00'); // null-terminated ASCII/UTF-8
	}

	// Map metadata to tags
	const mapped: { tag: number; value: string }[] = [];
	if (metadata['Description']) mapped.push({ tag: 0x010e, value: metadata['Description'] });
	if (metadata['Author']) mapped.push({ tag: 0x013b, value: metadata['Author'] });
	if (metadata['Copyright']) mapped.push({ tag: 0x8298, value: metadata['Copyright'] });

	// Collect unmapped keys -> include in Description JSON (appended)
	const unmapped: Record<string, string> = {};
	for (const k of Object.keys(metadata)) {
		if (!['Description', 'Author', 'Copyright'].includes(k)) unmapped[k] = metadata[k];
	}
	if (Object.keys(unmapped).length > 0) {
		const appended = JSON.stringify(unmapped);
		// if a Description already exists, append a separator and JSON; else create ImageDescription entry
		const existingDesc = mapped.find((m) => m.tag === 0x010e);
		if (existingDesc) existingDesc.value = existingDesc.value + '\n' + appended;
		else mapped.push({ tag: 0x010e, value: appended });
	}

	// Build entries with value bytes
	const entries = mapped.map((m) => ({ tag: m.tag, type: 2 /* ASCII */, data: asBytes(m.value) }));

	// Compute TIFF layout
	// TIFF header (8 bytes), entry count (2), entries (12 * n), nextIFD (4), then data blobs
	const tiffHeader = new Uint8Array(8);
	tiffHeader[0] = 0x49;
	tiffHeader[1] = 0x49; // 'II' little-endian
	tiffHeader[2] = 0x2a;
	tiffHeader[3] = 0x00; // 42
	// offset to 0th IFD (8)
	tiffHeader[4] = 0x08;
	tiffHeader[5] = 0x00;
	tiffHeader[6] = 0x00;
	tiffHeader[7] = 0x00;

	const entryCount = entries.length;
	const entryCountBytes = new Uint8Array(2);
	entryCountBytes[0] = entryCount & 0xff;
	entryCountBytes[1] = (entryCount >> 8) & 0xff;

	const entriesBytes = new Uint8Array(12 * entryCount);
	// data area starts after header + entryCount + entries + nextIFD (4)
	const dataOffsetBase = 8 + 2 + 12 * entryCount + 4;
	let cursor = dataOffsetBase;

	const dataBlobs: Uint8Array[] = [];

	for (let i = 0; i < entryCount; i++) {
		const e = entries[i];
		const off = i * 12;
		// tag (2 bytes little)
		entriesBytes[off] = e.tag & 0xff;
		entriesBytes[off + 1] = (e.tag >> 8) & 0xff;
		// type (2)
		entriesBytes[off + 2] = 2 & 0xff; // ASCII
		entriesBytes[off + 3] = 0x00;
		// count (4 bytes little)
		const count = e.data.length;
		entriesBytes[off + 4] = count & 0xff;
		entriesBytes[off + 5] = (count >> 8) & 0xff;
		entriesBytes[off + 6] = (count >> 16) & 0xff;
		entriesBytes[off + 7] = (count >> 24) & 0xff;
		// value_or_offset (4): if count <=4 could be inlined, but we will always put an offset (simpler)
		const offsetVal = cursor;
		entriesBytes[off + 8] = offsetVal & 0xff;
		entriesBytes[off + 9] = (offsetVal >> 8) & 0xff;
		entriesBytes[off + 10] = (offsetVal >> 16) & 0xff;
		entriesBytes[off + 11] = (offsetVal >> 24) & 0xff;
		dataBlobs.push(e.data);
		cursor += e.data.length;
	}

	// next IFD offset = 0
	const nextIfd = new Uint8Array(4); // zeros

	// assemble tiffTotal
	const tiffTotalLen = dataOffsetBase + dataBlobs.reduce((s, b) => s + b.length, 0);
	const tiffTotal = new Uint8Array(tiffTotalLen);
	let p = 0;
	tiffTotal.set(tiffHeader, p);
	p += tiffHeader.length;
	tiffTotal.set(entryCountBytes, p);
	p += entryCountBytes.length;
	tiffTotal.set(entriesBytes, p);
	p += entriesBytes.length;
	tiffTotal.set(nextIfd, p);
	p += nextIfd.length;
	for (const blob of dataBlobs) {
		tiffTotal.set(blob, p);
		p += blob.length;
	}

	// Exif header "Exif\0\0"
	const exifHeader = encoder.encode('Exif\0\0');
	const payload = new Uint8Array(exifHeader.length + tiffTotal.length);
	payload.set(exifHeader, 0);
	payload.set(tiffTotal, exifHeader.length);
	return payload;
}

/**
 * Insert EXIF APP1 payload into JPEG bytes immediately after SOI.
 * Returns new ArrayBuffer.
 */
function insertExifIntoJpeg(buffer: ArrayBuffer, metadata: Record<string, string>): ArrayBuffer {
	const u8 = new Uint8Array(buffer);
	if (u8.length < 2 || u8[0] !== 0xff || u8[1] !== 0xd8) return buffer;
	const payload = buildExifApp1PayloadFromMetadata(metadata);
	// APP1 marker: 0xFFE1, length (2 bytes big-endian) = payload.length + 2
	const app1Len = payload.length + 2;
	const totalLen = 2 + 2 + 2 + payload.length + (u8.length - 2);
	const out = new Uint8Array(totalLen);
	let pos = 0;
	out[pos++] = 0xff;
	out[pos++] = 0xd8; // SOI
	out[pos++] = 0xff;
	out[pos++] = 0xe1; // APP1
	out[pos++] = (app1Len >> 8) & 0xff;
	out[pos++] = app1Len & 0xff;
	out.set(payload, pos);
	pos += payload.length;
	out.set(u8.subarray(2), pos);
	return out.buffer;
}

/* ---------- PNG tEXt / SVG insertion (unchanged) ---------- */

function makeCrc32Table(): Uint32Array {
	const table = new Uint32Array(256);
	for (let i = 0; i < 256; i++) {
		let c = i;
		for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
		table[i] = c >>> 0;
	}
	return table;
}
const CRC32_TABLE = makeCrc32Table();
function crc32(buf: Uint8Array): number {
	let crc = 0xffffffff;
	for (let i = 0; i < buf.length; i++) crc = (CRC32_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8)) >>> 0;
	return (crc ^ 0xffffffff) >>> 0;
}
function makePngChunk(typeStr: string, data: Uint8Array): Uint8Array {
	const typeBytes = encoder.encode(typeStr);
	const len = data.length;
	const out = new Uint8Array(4 + 4 + len + 4);
	out[0] = (len >>> 24) & 0xff;
	out[1] = (len >>> 16) & 0xff;
	out[2] = (len >>> 8) & 0xff;
	out[3] = len & 0xff;
	out.set(typeBytes, 4);
	out.set(data, 8);
	const crcInput = new Uint8Array(typeBytes.length + data.length);
	crcInput.set(typeBytes, 0);
	crcInput.set(data, typeBytes.length);
	const crc = crc32(crcInput);
	const crcPos = 8 + len;
	out[crcPos] = (crc >>> 24) & 0xff;
	out[crcPos + 1] = (crc >>> 16) & 0xff;
	out[crcPos + 2] = (crc >>> 8) & 0xff;
	out[crcPos + 3] = crc & 0xff;
	return out;
}
function insertPngTextChunks(buffer: ArrayBuffer, metadata: Record<string, string>): ArrayBuffer {
	const u8 = new Uint8Array(buffer);
	const PNG_SIG = '\x89PNG\r\n\x1a\n';
	if (decoder.decode(u8.subarray(0, 8)) !== PNG_SIG) return buffer;
	let offset = 8;
	const chunksBefore: Uint8Array[] = [];
	let idatAt = -1;
	while (offset < u8.length) {
		if (offset + 8 > u8.length) break;
		const len = readUint32BE(u8, offset);
		const type = decoder.decode(u8.subarray(offset + 4, offset + 8));
		const chunkStart = offset;
		const chunkEnd = offset + 8 + len + 4;
		if (type === 'IDAT') {
			idatAt = chunkStart;
			break;
		}
		chunksBefore.push(u8.subarray(chunkStart, chunkEnd));
		offset = chunkEnd;
	}
	if (idatAt === -1) return buffer;
	const textChunks: Uint8Array[] = [];
	for (const [k, v] of Object.entries(metadata)) {
		const key = String(k).substring(0, 79);
		const val = String(v);
		const keyB = encoder.encode(key);
		const valB = encoder.encode(val);
		const combined = new Uint8Array(keyB.length + 1 + valB.length);
		combined.set(keyB, 0);
		combined[keyB.length] = 0;
		combined.set(valB, keyB.length + 1);
		textChunks.push(makePngChunk('tEXt', combined));
	}
	const rest = u8.subarray(idatAt);
	let total = 8;
	for (const c of chunksBefore) total += c.length;
	for (const c of textChunks) total += c.length;
	total += rest.length;
	const out = new Uint8Array(total);
	let p = 0;
	out.set(u8.subarray(0, 8), p);
	p += 8;
	for (const c of chunksBefore) {
		out.set(c, p);
		p += c.length;
	}
	for (const c of textChunks) {
		out.set(c, p);
		p += c.length;
	}
	out.set(rest, p);
	return out.buffer;
}

function escapeXmlName(name: string) {
	return name.replace(/[^A-Za-z0-9_:.-]/g, '_');
}
function insertSvgMetadata(svgBuffer: ArrayBuffer, metadata: Record<string, string>): ArrayBuffer {
	const txt = decoder.decode(svgBuffer);
	const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
	const md = `<metadata>${Object.entries(metadata)
		.map(([k, v]) => `<${escapeXmlName(k)}>${esc(v)}</${escapeXmlName(k)}>`)
		.join('')}</metadata>`;
	const pos = txt.indexOf('>');
	if (pos === -1) return toArrayBuffer(encoder.encode(md + txt));
	const out = encoder.encode(txt.slice(0, pos + 1) + md + txt.slice(pos + 1));
	return toArrayBuffer(out);
}

/* ---------- R2 helper ---------- */

async function putToR2(env: Env, key: string, body: ArrayBuffer | ArrayBufferView | ReadableStream, contentType?: string) {
	logInfo('putToR2', { key, contentType });
	await env.IMAGES_BUCKET.put(key, body, { httpMetadata: { contentType: contentType || 'application/octet-stream' } });
	logInfo('putToR2 OK', { key });
}

/* ---------- Watermark sizing helpers ---------- */

const MAX_WM_RATIO = 0.25; // watermark should not exceed 25% of main image width by default

function parseSizeToPixels(sizeRaw: string | undefined, mainWidth: number | undefined): number | undefined {
	if (!sizeRaw) return undefined;
	const s = String(sizeRaw).trim();
	if (s.endsWith('p') || s.endsWith('%')) {
		const num = parseFloat(s.slice(0, -1));
		if (Number.isNaN(num) || !mainWidth) return undefined;
		return Math.max(1, Math.round(mainWidth * (num / 100)));
	} else {
		const n = parseInt(s, 10);
		if (Number.isNaN(n) || n <= 0) return undefined;
		return n;
	}
}

/* ---------- Main worker ---------- */

export default {
	async fetch(request: Request, env: Env) {
		const url = new URL(request.url);

		if (request.method === 'GET' && url.pathname.startsWith('/r2/')) {
			const key = decodeURIComponent(url.pathname.replace('/r2/', ''));
			const obj = await env.IMAGES_BUCKET.get(key);
			if (!obj) return new Response('Not found', { status: 404 });
			const headers: Record<string, string> = {};
			if (obj.httpMetadata && obj.httpMetadata.contentType) headers['content-type'] = obj.httpMetadata.contentType;
			return new Response(obj.body, { status: 200, headers });
		}

		if (request.method === 'POST' && url.pathname === '/process') {
			logInfo('POST /process start');
			const form = await request.formData();
			const mainFile = form.get('main_file') as File | null;
			const mainUrl = (form.get('main_url') as string) || '';
			const wmFile = form.get('watermark_file') as File | null;
			const wmUrl = (form.get('watermark_url') as string) || '';
			const rawMeta = (form.get('metadata_json') as string) || null;
			const wmSizeRaw = (form.get('wm_size') as string) || '20p';
			const wmOpacityRaw = (form.get('wm_opacity') as string) || '60';
			const wmGravity = (form.get('wm_gravity') as string) || 'center';

			let meta: Record<string, string> = {};
			if (rawMeta) {
				try {
					meta = JSON.parse(rawMeta);
				} catch (e) {
					logError('invalid metadata_json', e);
					meta = {};
				}
			} else {
				for (const [k, v] of form.entries()) {
					if (typeof k === 'string' && k.startsWith('meta_')) meta[k.slice(5)] = String(v);
				}
			}

			// Load main image
			let mainBuf: ArrayBuffer;
			let mainCt: string | null = null;
			try {
				if (mainFile && mainFile.size > 0) {
					mainBuf = await mainFile.arrayBuffer();
					mainCt = mainFile.type || null;
					logInfo('main image uploaded file', { size: mainBuf.byteLength, contentType: mainCt });
				} else if (mainUrl) {
					const fetched = await fetchResource(mainUrl, 'main_url');
					mainBuf = fetched.buffer;
					mainCt = fetched.contentType;
					logInfo('main image fetched', { url: fetched.url, size: mainBuf.byteLength, contentType: mainCt });
				} else {
					return okJson({ error: 'No main image provided' }, 400);
				}
			} catch (err: any) {
				logError('Failed to load main image', err);
				return okJson({ error: `Failed to fetch main image: ${err?.message || String(err)}` }, 400);
			}

			// If user supplied metadata, require main image to be JPEG
			const hasMetadata = Object.keys(meta).length > 0;
			const mainIsJpeg = mainCt && (mainCt.includes('jpeg') || mainCt.includes('jpg'));
			if (hasMetadata && !mainIsJpeg) {
				return okJson({ error: 'EXIF metadata embedding only supported for JPEG main images. Provide a JPEG when metadata is used.' }, 400);
			}

			// compute deterministic R2 key
			const mainHash = await hashBufferHex(mainBuf);
			const mainExt = extFromContentType(mainCt);
			const mainKey = `main-${mainHash}.${mainExt}`;
			try {
				await putToR2(env, mainKey, mainBuf, mainCt || 'application/octet-stream');
			} catch (e) {
				logError('put main failed', e);
				return okJson({ error: 'Failed to store main image' }, 500);
			}

			// main dimensions
			let mainDims: { w: number; h: number } | null = null;
			if (mainCt && mainCt.includes('png')) mainDims = getPngDimensions(mainBuf);
			else if (mainCt && (mainCt.includes('jpeg') || mainCt.includes('jpg'))) mainDims = getJpegDimensions(mainBuf);
			logInfo('main dims', { mainDims });

			// Handle watermark (optional)
			let watermarkKey: string | null = null;
			let wmBuf: ArrayBuffer | null = null;
			let wmCt: string | null = null;
			let wmDims: { w: number; h: number } | null = null;
			try {
				if (wmFile && wmFile.size > 0) {
					wmBuf = await wmFile.arrayBuffer();
					wmCt = wmFile.type || null;
					logInfo('watermark uploaded', { size: wmBuf.byteLength, contentType: wmCt });
				} else if (wmUrl) {
					const fetched = await fetchResource(wmUrl, 'watermark_url');
					wmBuf = fetched.buffer;
					wmCt = fetched.contentType;
					logInfo('watermark fetched', { url: fetched.url, size: wmBuf.byteLength, contentType: wmCt });
				}
				if (wmBuf) {
					if (wmCt && wmCt.includes('png')) wmDims = getPngDimensions(wmBuf);
					else if (wmCt && (wmCt.includes('jpeg') || wmCt.includes('jpg'))) wmDims = getJpegDimensions(wmBuf);
					const wmHash = await hashBufferHex(wmBuf);
					const wmExt = extFromContentType(wmCt);
					watermarkKey = `wm-${wmHash}.${wmExt}`;
					await putToR2(env, watermarkKey, wmBuf, wmCt || 'application/octet-stream');
				}
			} catch (err: any) {
				logError('watermark fetch/store failed', err);
				return okJson({ error: `Failed to fetch/store watermark: ${err?.message || String(err)}` }, 400);
			}

			// Determine overlay width in px
			let overlayWidthPx = parseSizeToPixels(wmSizeRaw, mainDims?.w);
			if (!overlayWidthPx && mainDims?.w) overlayWidthPx = Math.max(1, Math.round(mainDims.w * 0.2));

			// Prevent watermark from covering entire image:
			if (mainDims?.w && overlayWidthPx) {
				const maxAllowed = Math.max(1, Math.round(mainDims.w * MAX_WM_RATIO));
				if (overlayWidthPx >= mainDims.w) {
					logInfo('overlayWidthPx exceeds main width, clamping', { overlayWidthPx, mainWidth: mainDims.w, maxAllowed });
					overlayWidthPx = maxAllowed;
				} else if (overlayWidthPx > maxAllowed) {
					logInfo('overlayWidthPx larger than policy max, clamping to maxAllowed', { overlayWidthPx, maxAllowed });
					overlayWidthPx = maxAllowed;
				}
			}

			// Normalize opacity to 0..1
			let opacity = parseFloat(wmOpacityRaw);
			if (Number.isNaN(opacity)) opacity = 0.6;
			if (opacity > 1) opacity = Math.min(1, opacity / 100);

			// Build transform draw options
			const origin = new URL(request.url).origin;
			const mainR2Url = `${origin}/r2/${encodeURIComponent(mainKey)}`;

			const transformOptions: any = { cf: { image: {} } };
			if (watermarkKey) {
				const wmR2Url = `${origin}/r2/${encodeURIComponent(watermarkKey)}`;
				const drawObj: any = { url: wmR2Url, opacity };
				if (overlayWidthPx) drawObj.width = overlayWidthPx; // integer px
				if (wmGravity && wmGravity !== 'center') drawObj.gravity = wmGravity;
				transformOptions.cf.image.draw = [drawObj];
			} else {
				transformOptions.cf.image = {};
			}
			transformOptions.headers = { 'User-Agent': USER_AGENT };

			// Request transform
			let transformed: Response;
			try {
				logInfo('calling transform', { mainR2Url, draw: transformOptions.cf.image.draw });
				transformed = await fetch(mainR2Url, transformOptions);
			} catch (err) {
				logError('transform network failure', err);
				return okJson({ error: 'Image transform network failure' }, 500);
			}
			if (!transformed.ok) {
				const snippet = await transformed
					.clone()
					.text()
					.catch(() => '');
				logError('transform returned non-OK', {
					status: transformed.status,
					statusText: transformed.statusText,
					snippet: snippet.slice ? snippet.slice(0, 200) : '',
				});
				return okJson({ error: `Image transform failed: ${transformed.status} ${transformed.statusText}` }, 500);
			}

			let outBuf: ArrayBuffer;
			try {
				outBuf = await transformed.arrayBuffer();
			} catch (err) {
				logError('reading transform body failed', err);
				return okJson({ error: 'Failed to read transformed image' }, 500);
			}
			const outCt = transformed.headers.get('content-type') || mainCt || 'application/octet-stream';
			logInfo('transform returned', { outCt, bytes: outBuf.byteLength });

			// Embed metadata: JPEG EXIF only (now multi-field)
			try {
				if ((outCt.includes('jpeg') || outCt.includes('jpg')) && hasMetadata) {
					outBuf = insertExifIntoJpeg(outBuf, meta);
					logInfo('Inserted EXIF into JPEG (multi-field)');
				} else if (outCt.includes('png') && Object.keys(meta).length) {
					outBuf = insertPngTextChunks(outBuf, meta);
					logInfo('Inserted tEXt into PNG');
				} else if (outCt.includes('svg') && Object.keys(meta).length) {
					outBuf = insertSvgMetadata(outBuf, meta);
					logInfo('Inserted metadata into SVG');
				} else {
					logInfo('No metadata insertion for content type', { outCt });
				}
			} catch (err) {
				logError('metadata insertion failed (non-fatal)', err);
			}

			const headers = new Headers({ 'Content-Type': outCt });
			headers.set('Content-Disposition', `inline; filename="protected-${mainKey}"`);
			logInfo('responding with protected image', { mainKey, watermarkKey });
			return new Response(outBuf, { status: 200, headers });
		}

		if (request.method === 'GET') {
			return new Response('Image Protector Worker', { headers: { 'content-type': 'text/plain' } });
		}
		return new Response('Method not allowed', { status: 405 });
	},
};
