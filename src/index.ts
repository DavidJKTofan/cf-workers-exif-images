/**
 * src/index.ts
 *
 * Cloudflare Workers Image Protector - Production-Ready
 *
 * Improvements:
 * - SSRF protection (blocks private IPs, localhost, metadata endpoints)
 * - File size validation (configurable limits)
 * - Magic number verification for image formats
 * - Request timeouts on external fetches
 * - Sanitized error messages (no internal detail leakage)
 * - Structured logging with correlation IDs
 * - Performance metrics and timing
 * - R2 caching strategy
 * - Rate limiting preparation
 */

const USER_AGENT = `Cloudflare-Image-Protector/1.0 (+https://example.com)`;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

// Configuration
const CONFIG = {
	MAX_FILE_SIZE: 10 * 1024 * 1024, // 10MB
	MAX_METADATA_SIZE: 10 * 1024, // 10KB
	MAX_DIMENSION: 10000, // 10k pixels
	FETCH_TIMEOUT: 15000, // 15 seconds
	MAX_WM_RATIO: 0.25, // watermark max 25% of main width
};

interface Env {
	IMAGES_BUCKET: R2Bucket;
}

interface LogContext {
	requestId: string;
	timestamp: number;
}

let globalLogContext: LogContext = { requestId: '', timestamp: 0 };

function logInfo(message: string, data?: any) {
	try {
		console.log(
			JSON.stringify({
				level: 'info',
				requestId: globalLogContext.requestId,
				message,
				data,
				timestamp: new Date().toISOString(),
			})
		);
	} catch (_) {}
}

function logError(message: string, error?: any) {
	try {
		const errorData: any = {};
		if (error) {
			if (error instanceof Error) {
				errorData.message = error.message;
				errorData.stack = error.stack;
				errorData.name = error.name;
			} else if (typeof error === 'object') {
				errorData.details = JSON.stringify(error);
			} else {
				errorData.value = String(error);
			}
		}

		console.error(
			JSON.stringify({
				level: 'error',
				requestId: globalLogContext.requestId,
				message,
				error: errorData,
				timestamp: new Date().toISOString(),
			})
		);
	} catch (_) {}
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
	if (ct.includes('jpeg') || ct.includes('jpg')) return 'jpg';
	if (ct.includes('png')) return 'png';
	if (ct.includes('svg')) return 'svg';
	if (ct.includes('webp')) return 'webp';
	if (ct.includes('heic') || ct.includes('heif')) return 'heic';
	return 'bin';
}

function okJson(body: any, status = 200) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'content-type': 'application/json;charset=utf-8' },
	});
}

function readUint32BE(u8: Uint8Array, offset: number) {
	return (u8[offset] << 24) | (u8[offset + 1] << 16) | (u8[offset + 2] << 8) | u8[offset + 3];
}

function toArrayBuffer(u: Uint8Array): ArrayBuffer {
	return ArrayBuffer.prototype.slice.call(u.buffer, u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
}

/* ---------- Text to SVG watermark generator ---------- */

function generateTextSvg(
	text: string,
	options: {
		size?: number;
		color?: string;
		font?: string;
		weight?: string;
	}
): string {
	const size = options.size || 48;
	const color = options.color || '#ffffff';
	const font = options.font || 'sans-serif';
	const weight = options.weight || 'bold';

	// Escape XML special characters
	const escapeXml = (s: string) =>
		s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');

	const escapedText = escapeXml(text);

	// Estimate text width (rough approximation: 0.6 * fontSize * characterCount)
	const estimatedWidth = Math.ceil(size * 0.6 * text.length);
	const height = Math.ceil(size * 1.5); // Give some vertical padding
	const width = Math.max(estimatedWidth, size * 2); // Minimum width

	// Add semi-transparent background for better visibility
	// This helps ensure the text is readable against any background
	const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">
  <rect width="100%" height="100%" fill="black" opacity="0.5"/>
  <text 
    x="50%" 
    y="50%" 
    font-family="${escapeXml(font)}" 
    font-size="${size}" 
    font-weight="${weight}" 
    fill="${escapeXml(color)}" 
    text-anchor="middle" 
    dominant-baseline="middle">${escapedText}</text>
</svg>`;

	return svg;
}

/* ---------- SSRF Protection ---------- */

function isPrivateIP(hostname: string): boolean {
	// IPv4 private ranges
	const ipv4Private = [
		/^127\./, // localhost
		/^10\./, // 10.0.0.0/8
		/^172\.(1[6-9]|2[0-9]|3[01])\./, // 172.16.0.0/12
		/^192\.168\./, // 192.168.0.0/16
		/^169\.254\./, // link-local (AWS metadata)
		/^0\.0\.0\.0$/, // unspecified
	];

	// IPv6 private ranges
	const ipv6Private = [
		/^::1$/, // localhost
		/^fe80:/i, // link-local
		/^fc00:/i, // unique local
		/^fd[0-9a-f]{2}:/i, // unique local
	];

	const lower = hostname.toLowerCase();

	if (lower === 'localhost') return true;

	for (const pattern of ipv4Private) {
		if (pattern.test(lower)) return true;
	}

	for (const pattern of ipv6Private) {
		if (pattern.test(lower)) return true;
	}

	return false;
}

function validateUrl(urlStr: string): { valid: boolean; url?: URL; error?: string } {
	try {
		const url = new URL(urlStr);

		if (!['http:', 'https:'].includes(url.protocol)) {
			return { valid: false, error: 'Only HTTP/HTTPS protocols allowed' };
		}

		if (isPrivateIP(url.hostname)) {
			return { valid: false, error: 'Private IP addresses not allowed' };
		}

		return { valid: true, url };
	} catch (err) {
		return { valid: false, error: 'Invalid URL format' };
	}
}

/* ---------- Image Format Verification ---------- */

function verifyImageFormat(buffer: ArrayBuffer): { valid: boolean; type: string; error?: string } {
	const u8 = new Uint8Array(buffer);

	logInfo('Verifying image format', {
		bufferSize: buffer.byteLength,
		firstBytes: Array.from(u8.slice(0, 16))
			.map((b) => '0x' + b.toString(16).padStart(2, '0'))
			.join(' '),
	});

	if (u8.length < 8) {
		return { valid: false, type: '', error: 'File too small to be valid image' };
	}

	// JPEG magic number: FF D8 FF
	if (u8[0] === 0xff && u8[1] === 0xd8 && u8[2] === 0xff) {
		logInfo('Detected format: JPEG');
		return { valid: true, type: 'image/jpeg' };
	}

	// PNG magic number: 89 50 4E 47 0D 0A 1A 0A
	const pngSig = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
	let isPng = true;
	for (let i = 0; i < 8; i++) {
		if (u8[i] !== pngSig[i]) {
			isPng = false;
			break;
		}
	}
	if (isPng) {
		logInfo('Detected format: PNG');
		return { valid: true, type: 'image/png' };
	}

	// WebP magic number: RIFF....WEBP
	if (
		u8.length >= 12 &&
		u8[0] === 0x52 &&
		u8[1] === 0x49 &&
		u8[2] === 0x46 &&
		u8[3] === 0x46 && // RIFF
		u8[8] === 0x57 &&
		u8[9] === 0x45 &&
		u8[10] === 0x42 &&
		u8[11] === 0x50
	) {
		// WEBP
		logInfo('Detected format: WebP');
		return { valid: true, type: 'image/webp' };
	}

	// GIF magic number: GIF87a or GIF89a
	if (
		u8.length >= 6 &&
		u8[0] === 0x47 &&
		u8[1] === 0x49 &&
		u8[2] === 0x46 && // GIF
		u8[3] === 0x38 &&
		(u8[4] === 0x37 || u8[4] === 0x39) &&
		u8[5] === 0x61
	) {
		// 87a or 89a
		logInfo('Detected format: GIF');
		return { valid: true, type: 'image/gif' };
	}

	// SVG (text-based format)
	try {
		const textStart = decoder.decode(u8.subarray(0, Math.min(500, u8.length)));
		if (textStart.includes('<svg') || (textStart.includes('<?xml') && textStart.includes('<svg'))) {
			logInfo('Detected format: SVG');
			return { valid: true, type: 'image/svg+xml' };
		}
	} catch (e) {
		// Not valid UTF-8, can't be SVG
	}

	// BMP magic number: BM
	if (u8.length >= 2 && u8[0] === 0x42 && u8[1] === 0x4d) {
		logInfo('Detected format: BMP');
		return { valid: true, type: 'image/bmp' };
	}

	// TIFF magic numbers: II (little-endian) or MM (big-endian)
	if (
		u8.length >= 4 &&
		((u8[0] === 0x49 && u8[1] === 0x49 && u8[2] === 0x2a && u8[3] === 0x00) ||
			(u8[0] === 0x4d && u8[1] === 0x4d && u8[2] === 0x00 && u8[3] === 0x2a))
	) {
		logInfo('Detected format: TIFF');
		return { valid: true, type: 'image/tiff' };
	}

	logError('Unsupported image format', {
		bufferSize: u8.length,
		firstBytes: Array.from(u8.slice(0, 16))
			.map((b) => '0x' + b.toString(16).padStart(2, '0'))
			.join(' '),
	});

	return { valid: false, type: '', error: 'Unsupported image format' };
}

/* ---------- Dimension parsers (PNG / JPEG) ---------- */

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

function validateDimensions(dims: { w: number; h: number } | null): boolean {
	if (!dims) return false;
	return dims.w > 0 && dims.h > 0 && dims.w <= CONFIG.MAX_DIMENSION && dims.h <= CONFIG.MAX_DIMENSION;
}

/* ---------- Fetch with timeout and validation ---------- */

async function fetchResource(urlStr: string, label: string) {
	const trimmed = urlStr.trim();

	logInfo(`Starting fetch for ${label}`, { url: trimmed });

	// Validate URL
	const validation = validateUrl(trimmed);
	if (!validation.valid) {
		logError(`URL validation failed for ${label}`, { url: trimmed, reason: validation.error });
		throw new Error(`${label}: ${validation.error}`);
	}

	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), CONFIG.FETCH_TIMEOUT);

	try {
		const res = await fetch(trimmed, {
			signal: controller.signal,
			redirect: 'follow',
			headers: {
				'User-Agent': USER_AGENT,
				Accept: 'image/*,*/*;q=0.8',
			},
		});

		clearTimeout(timeoutId);

		logInfo(`Fetch response for ${label}`, {
			url: trimmed,
			status: res.status,
			statusText: res.statusText,
			contentType: res.headers.get('content-type'),
			contentLength: res.headers.get('content-length'),
		});

		if (!res.ok) {
			throw new Error(`HTTP ${res.status}`);
		}

		const buf = await res.arrayBuffer();

		// Validate size
		if (buf.byteLength > CONFIG.MAX_FILE_SIZE) {
			logError(`File exceeds size limit for ${label}`, {
				size: buf.byteLength,
				limit: CONFIG.MAX_FILE_SIZE,
			});
			throw new Error(`File exceeds maximum size of ${CONFIG.MAX_FILE_SIZE} bytes`);
		}

		const ct = res.headers.get('content-type') || 'application/octet-stream';

		logInfo(`Fetch successful for ${label}`, {
			url: trimmed,
			bytes: buf.byteLength,
			contentType: ct,
		});

		return { buffer: buf, contentType: ct, url: trimmed };
	} catch (err: any) {
		clearTimeout(timeoutId);

		if (err.name === 'AbortError') {
			logError(`${label} fetch timeout`, { url: trimmed, timeout: CONFIG.FETCH_TIMEOUT });
			throw new Error(`${label} fetch timeout after ${CONFIG.FETCH_TIMEOUT}ms`);
		}

		logError(`${label} fetch failed`, {
			url: trimmed,
			error: err.message || String(err),
			stack: err.stack,
		});
		throw new Error(`${label} fetch failed`);
	}
}

/* ---------- EXIF APP1 builder (multiple 0th IFD ASCII tags) ---------- */

function buildExifApp1PayloadFromMetadata(metadata: Record<string, string>): Uint8Array {
	function asBytes(s: string) {
		return encoder.encode(s + '\x00');
	}

	const mapped: { tag: number; value: string }[] = [];
	if (metadata['Description']) mapped.push({ tag: 0x010e, value: metadata['Description'] });
	if (metadata['Author']) mapped.push({ tag: 0x013b, value: metadata['Author'] });
	if (metadata['Copyright']) mapped.push({ tag: 0x8298, value: metadata['Copyright'] });

	const unmapped: Record<string, string> = {};
	for (const k of Object.keys(metadata)) {
		if (!['Description', 'Author', 'Copyright'].includes(k)) unmapped[k] = metadata[k];
	}
	if (Object.keys(unmapped).length > 0) {
		const appended = JSON.stringify(unmapped);
		const existingDesc = mapped.find((m) => m.tag === 0x010e);
		if (existingDesc) existingDesc.value = existingDesc.value + '\n' + appended;
		else mapped.push({ tag: 0x010e, value: appended });
	}

	const entries = mapped.map((m) => ({ tag: m.tag, type: 2, data: asBytes(m.value) }));

	const tiffHeader = new Uint8Array(8);
	tiffHeader[0] = 0x49;
	tiffHeader[1] = 0x49;
	tiffHeader[2] = 0x2a;
	tiffHeader[3] = 0x00;
	tiffHeader[4] = 0x08;
	tiffHeader[5] = 0x00;
	tiffHeader[6] = 0x00;
	tiffHeader[7] = 0x00;

	const entryCount = entries.length;
	const entryCountBytes = new Uint8Array(2);
	entryCountBytes[0] = entryCount & 0xff;
	entryCountBytes[1] = (entryCount >> 8) & 0xff;

	const entriesBytes = new Uint8Array(12 * entryCount);
	const dataOffsetBase = 8 + 2 + 12 * entryCount + 4;
	let cursor = dataOffsetBase;
	const dataBlobs: Uint8Array[] = [];

	for (let i = 0; i < entryCount; i++) {
		const e = entries[i];
		const off = i * 12;
		entriesBytes[off] = e.tag & 0xff;
		entriesBytes[off + 1] = (e.tag >> 8) & 0xff;
		entriesBytes[off + 2] = 2 & 0xff;
		entriesBytes[off + 3] = 0x00;
		const count = e.data.length;
		entriesBytes[off + 4] = count & 0xff;
		entriesBytes[off + 5] = (count >> 8) & 0xff;
		entriesBytes[off + 6] = (count >> 16) & 0xff;
		entriesBytes[off + 7] = (count >> 24) & 0xff;
		const offsetVal = cursor;
		entriesBytes[off + 8] = offsetVal & 0xff;
		entriesBytes[off + 9] = (offsetVal >> 8) & 0xff;
		entriesBytes[off + 10] = (offsetVal >> 16) & 0xff;
		entriesBytes[off + 11] = (offsetVal >> 24) & 0xff;
		dataBlobs.push(e.data);
		cursor += e.data.length;
	}

	const nextIfd = new Uint8Array(4);
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

	const exifHeader = encoder.encode('Exif\0\0');
	const payload = new Uint8Array(exifHeader.length + tiffTotal.length);
	payload.set(exifHeader, 0);
	payload.set(tiffTotal, exifHeader.length);
	return payload;
}

function insertExifIntoJpeg(buffer: ArrayBuffer, metadata: Record<string, string>): ArrayBuffer {
	const u8 = new Uint8Array(buffer);
	if (u8.length < 2 || u8[0] !== 0xff || u8[1] !== 0xd8) return buffer;
	const payload = buildExifApp1PayloadFromMetadata(metadata);
	const app1Len = payload.length + 2;
	const totalLen = 2 + 2 + 2 + payload.length + (u8.length - 2);
	const out = new Uint8Array(totalLen);
	let pos = 0;
	out[pos++] = 0xff;
	out[pos++] = 0xd8;
	out[pos++] = 0xff;
	out[pos++] = 0xe1;
	out[pos++] = (app1Len >> 8) & 0xff;
	out[pos++] = app1Len & 0xff;
	out.set(payload, pos);
	pos += payload.length;
	out.set(u8.subarray(2), pos);
	return out.buffer;
}

/* ---------- PNG tEXt insertion ---------- */

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
	const crcVal = crc32(crcInput);
	const crcPos = 8 + len;
	out[crcPos] = (crcVal >>> 24) & 0xff;
	out[crcPos + 1] = (crcVal >>> 16) & 0xff;
	out[crcPos + 2] = (crcVal >>> 8) & 0xff;
	out[crcPos + 3] = crcVal & 0xff;
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

/* ---------- SVG metadata insertion ---------- */

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
	logInfo('Uploading to R2', { key, contentType });

	const existing = await env.IMAGES_BUCKET.head(key);
	if (existing) {
		logInfo('Key already exists in R2, skipping upload', { key });
		return;
	}

	await env.IMAGES_BUCKET.put(key, body, {
		httpMetadata: {
			contentType: contentType || 'application/octet-stream',
			cacheControl: 'public, max-age=31536000, immutable',
		},
	});

	logInfo('R2 upload complete', { key });
}

/* ---------- Watermark sizing helpers ---------- */

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

/* ---------- Main fetch handler ---------- */

export default {
	async fetch(request: Request, env: Env) {
		const startTime = Date.now();
		globalLogContext = {
			requestId: crypto.randomUUID(),
			timestamp: startTime,
		};

		const url = new URL(request.url);
		const requestOrigin = url.origin;

		try {
			// Serve R2 via /r2/<key>
			if (request.method === 'GET' && url.pathname.startsWith('/r2/')) {
				const key = decodeURIComponent(url.pathname.replace('/r2/', ''));

				if (!key || key.includes('..')) {
					return new Response('Invalid key', { status: 400 });
				}

				const obj = await env.IMAGES_BUCKET.get(key);
				if (!obj) return new Response('Not found', { status: 404 });

				const headers: Record<string, string> = {
					'Cache-Control': 'public, max-age=31536000, immutable',
				};

				if (obj.httpMetadata && obj.httpMetadata.contentType) {
					headers['content-type'] = obj.httpMetadata.contentType;
				}

				return new Response(obj.body, { status: 200, headers });
			}

			// Process
			if (request.method === 'POST' && url.pathname === '/process') {
				logInfo('Processing image request', { method: 'POST', path: '/process' });

				const form = await request.formData();

				// Log all form entries for debugging
				const formEntries: Record<string, any> = {};
				for (const [key, value] of form.entries()) {
					if (value instanceof File) {
						formEntries[key] = `File: ${value.name} (${value.size} bytes)`;
					} else {
						formEntries[key] = value;
					}
				}
				logInfo('Form data received', { entries: formEntries });

				const mainFile = form.get('main_file') as File | null;
				const mainUrl = (form.get('main_url') as string) || '';
				const wmFile = form.get('watermark_file') as File | null;
				const wmUrl = (form.get('watermark_url') as string) || '';
				const wmText = (form.get('watermark_text') as string) || '';
				const rawMeta = (form.get('metadata_json') as string) || null;
				const wmSizeRaw = (form.get('wm_size') as string) || '20p';
				const wmOpacityRaw = (form.get('wm_opacity') as string) || '60';
				const wmGravity = (form.get('wm_gravity') as string) || 'center';

				// Text watermark specific options
				const wmTextColor = (form.get('wm_text_color') as string) || 'white';
				const wmTextSize = (form.get('wm_text_size') as string) || '48';
				const wmTextFont = (form.get('wm_text_font') as string) || 'sans-serif';
				const wmTextWeight = (form.get('wm_text_weight') as string) || 'bold';

				logInfo('Parsed watermark parameters', {
					hasWmFile: !!(wmFile && wmFile.size > 0),
					hasWmUrl: !!(wmUrl && wmUrl.trim()),
					hasWmText: !!(wmText && wmText.trim()),
					wmText: wmText || '(empty)',
					wmTextSize,
					wmTextColor,
					wmTextFont,
					wmTextWeight,
				});

				// Validate metadata size
				if (rawMeta && rawMeta.length > CONFIG.MAX_METADATA_SIZE) {
					return okJson({ error: 'Metadata too large' }, 413);
				}

				let meta: Record<string, string> = {};
				if (rawMeta) {
					try {
						meta = JSON.parse(rawMeta);
						if (typeof meta !== 'object' || Array.isArray(meta)) {
							meta = {};
						}
					} catch (e) {
						logError('Invalid metadata_json', e);
						return okJson({ error: 'Invalid metadata JSON' }, 400);
					}
				} else {
					for (const [k, v] of form.entries()) {
						if (typeof k === 'string' && k.startsWith('meta_')) {
							meta[k.replace('meta_', '')] = String(v);
						}
					}
				}

				// Load main image
				let mainBuf: ArrayBuffer;
				let mainCt: string | null = null;
				try {
					if (mainFile && mainFile.size > 0) {
						if (mainFile.size > CONFIG.MAX_FILE_SIZE) {
							return okJson({ error: `Main file too large. Maximum: ${CONFIG.MAX_FILE_SIZE} bytes` }, 413);
						}
						mainBuf = await mainFile.arrayBuffer();
						mainCt = mainFile.type || null;
						logInfo('Main image uploaded', { size: mainBuf.byteLength });
					} else if (mainUrl) {
						const fetched = await fetchResource(mainUrl, 'main image');
						mainBuf = fetched.buffer;
						mainCt = fetched.contentType;
					} else {
						return okJson({ error: 'No main image provided' }, 400);
					}
				} catch (err: any) {
					logError('Failed to load main image', err);
					return okJson({ error: 'Failed to load main image' }, 400);
				}

				// Verify image format with magic numbers
				const formatCheck = verifyImageFormat(mainBuf);
				if (!formatCheck.valid) {
					logError('Invalid main image format', { error: formatCheck.error });
					return okJson({ error: formatCheck.error || 'Invalid image format' }, 400);
				}
				mainCt = formatCheck.type;

				const hasMetadata = Object.keys(meta).length > 0;
				const mainIsJpeg = mainCt && (mainCt.includes('jpeg') || mainCt.includes('jpg'));

				if (hasMetadata && !mainIsJpeg) {
					return okJson(
						{
							error: 'EXIF metadata embedding only supported for JPEG images. Provide a JPEG when metadata is used.',
						},
						400
					);
				}

				// Store main image to R2
				const mainHash = await hashBufferHex(mainBuf);
				const mainExt = extFromContentType(mainCt);
				const mainKey = `main-${mainHash}.${mainExt}`;

				try {
					await putToR2(env, mainKey, mainBuf, mainCt);
				} catch (e) {
					logError('Failed to store main image', e);
					return okJson({ error: 'Failed to store main image' }, 500);
				}

				// Get and validate main dimensions
				let mainDims: { w: number; h: number } | null = null;
				if (mainCt.includes('png')) {
					mainDims = getPngDimensions(mainBuf);
				} else if (mainCt.includes('jpeg') || mainCt.includes('jpg')) {
					mainDims = getJpegDimensions(mainBuf);
				}

				if (mainDims && !validateDimensions(mainDims)) {
					logError('Main image dimensions invalid', { dims: mainDims });
					return okJson({ error: 'Image dimensions invalid or too large' }, 400);
				}

				logInfo('Main image processed', { dims: mainDims });

				// Determine watermark type (file, URL, or text)
				let watermarkType: 'none' | 'image' | 'text' = 'none';
				let textSvgKey: string | null = null;

				if (wmText && wmText.trim().length > 0) {
					watermarkType = 'text';
				} else if ((wmFile && wmFile.size > 0) || (wmUrl && wmUrl.trim().length > 0)) {
					watermarkType = 'image';
				}

				logInfo('Watermark type determined', {
					type: watermarkType,
					hasFile: !!(wmFile && wmFile.size > 0),
					hasUrl: !!(wmUrl && wmUrl.trim().length > 0),
					hasText: !!(wmText && wmText.trim().length > 0),
				});

				// Generate SVG for text watermark and convert to PNG
				if (watermarkType === 'text') {
					try {
						logInfo('Generating SVG from text watermark', {
							text: wmText.trim(),
							size: wmTextSize,
							color: wmTextColor,
							font: wmTextFont,
							weight: wmTextWeight,
						});

						const textSize = parseInt(wmTextSize, 10);
						const validatedSize = isNaN(textSize) ? 48 : Math.min(Math.max(textSize, 12), 500);

						const svgContent = generateTextSvg(wmText.trim(), {
							size: validatedSize,
							color: wmTextColor,
							font: wmTextFont,
							weight: wmTextWeight,
						});

						const svgBuffer = encoder.encode(svgContent);
						const svgHash = await hashBufferHex(toArrayBuffer(svgBuffer));
						const svgKey = `text-wm-svg-${svgHash}.svg`;

						logInfo('Generated SVG watermark', {
							key: svgKey,
							size: svgBuffer.length,
							textLength: wmText.trim().length,
						});

						// Store SVG to R2
						await putToR2(env, svgKey, toArrayBuffer(svgBuffer), 'image/svg+xml');
						logInfo('Text SVG stored to R2', { key: svgKey });

						// Convert SVG to PNG using Cloudflare Image Resizing
						// This is necessary because draw overlays don't support SVG
						const svgR2Url = `${requestOrigin}/r2/${encodeURIComponent(svgKey)}`;

						logInfo('Converting SVG to PNG via image transform', { svgUrl: svgR2Url });

						const pngResponse = await fetch(svgR2Url, {
							cf: {
								image: {
									format: 'png',
									quality: 100,
								},
							},
							headers: { 'User-Agent': USER_AGENT },
						});

						if (!pngResponse.ok) {
							logError('Failed to convert SVG to PNG', {
								status: pngResponse.status,
								statusText: pngResponse.statusText,
							});
							return okJson({ error: 'Failed to convert text watermark to PNG' }, 500);
						}

						const pngBuffer = await pngResponse.arrayBuffer();
						const pngHash = await hashBufferHex(pngBuffer);
						textSvgKey = `text-wm-${pngHash}.png`;

						logInfo('Converted SVG to PNG', {
							key: textSvgKey,
							size: pngBuffer.byteLength,
						});

						// Store PNG to R2
						await putToR2(env, textSvgKey, pngBuffer, 'image/png');

						logInfo('Text PNG watermark stored to R2', { key: textSvgKey });
					} catch (err: any) {
						logError('Failed to generate text watermark', {
							error: err.message || String(err),
							stack: err.stack,
						});
						return okJson({ error: 'Failed to generate text watermark' }, 500);
					}
				}

				// Load image watermark (if type is 'image')
				let watermarkKey: string | null = null;
				let wmBuf: ArrayBuffer | null = null;
				let wmCt: string | null = null;
				let wmDims: { w: number; h: number } | null = null;

				if (watermarkType === 'image') {
					try {
						logInfo('Processing watermark', {
							hasFile: !!(wmFile && wmFile.size > 0),
							hasUrl: !!(wmUrl && wmUrl.trim().length > 0),
							urlProvided: wmUrl,
						});

						if (wmFile && wmFile.size > 0) {
							if (wmFile.size > CONFIG.MAX_FILE_SIZE) {
								return okJson({ error: `Watermark file too large. Maximum: ${CONFIG.MAX_FILE_SIZE} bytes` }, 413);
							}
							wmBuf = await wmFile.arrayBuffer();
							wmCt = wmFile.type || null;
							logInfo('Watermark uploaded', { size: wmBuf.byteLength, claimedType: wmCt });
						} else if (wmUrl && wmUrl.trim().length > 0) {
							const fetched = await fetchResource(wmUrl, 'watermark');
							wmBuf = fetched.buffer;
							wmCt = fetched.contentType;
						}

						if (wmBuf) {
							logInfo('Verifying watermark format', {
								bufferSize: wmBuf.byteLength,
								claimedContentType: wmCt,
							});

							// Verify watermark format
							const wmFormatCheck = verifyImageFormat(wmBuf);
							if (!wmFormatCheck.valid) {
								logError('Invalid watermark format', {
									error: wmFormatCheck.error,
									claimedType: wmCt,
									bufferSize: wmBuf.byteLength,
								});
								return okJson({ error: `Invalid watermark format: ${wmFormatCheck.error}` }, 400);
							}
							wmCt = wmFormatCheck.type;

							logInfo('Watermark format verified', { detectedType: wmCt });

							// Get watermark dimensions
							if (wmCt.includes('png')) {
								wmDims = getPngDimensions(wmBuf);
							} else if (wmCt.includes('jpeg') || wmCt.includes('jpg')) {
								wmDims = getJpegDimensions(wmBuf);
							}

							if (wmDims) {
								logInfo('Watermark dimensions extracted', { width: wmDims.w, height: wmDims.h });

								if (!validateDimensions(wmDims)) {
									logError('Watermark dimensions invalid', {
										dims: wmDims,
										maxAllowed: CONFIG.MAX_DIMENSION,
									});
									return okJson({ error: 'Watermark dimensions invalid or too large' }, 400);
								}
							} else {
								logInfo('Could not extract watermark dimensions (non-critical)');
							}

							const wmHash = await hashBufferHex(wmBuf);
							const wmExt = extFromContentType(wmCt);
							watermarkKey = `wm-${wmHash}.${wmExt}`;

							logInfo('Storing watermark to R2', { key: watermarkKey });
							await putToR2(env, watermarkKey, wmBuf, wmCt);

							logInfo('Watermark processed successfully', {
								dims: wmDims,
								key: watermarkKey,
								type: wmCt,
							});
						}
					} catch (err: any) {
						logError('Watermark processing failed', {
							error: err.message || String(err),
							stack: err.stack,
						});
						return okJson({ error: 'Failed to process watermark' }, 400);
					}
				} else {
					logInfo('No image watermark provided');
				}

				// Calculate overlay width (for image watermarks only)
				let overlayWidthPx: number | undefined = undefined;
				if (watermarkType === 'image') {
					overlayWidthPx = parseSizeToPixels(wmSizeRaw, mainDims?.w);
					if (!overlayWidthPx && mainDims?.w) {
						overlayWidthPx = Math.max(1, Math.round(mainDims.w * 0.2));
					}

					// Clamp to policy - avoid covering entire image
					if (mainDims?.w && overlayWidthPx) {
						const maxAllowed = Math.max(1, Math.round(mainDims.w * CONFIG.MAX_WM_RATIO));
						if (overlayWidthPx >= mainDims.w) {
							overlayWidthPx = maxAllowed;
						} else if (overlayWidthPx > maxAllowed) {
							overlayWidthPx = maxAllowed;
						}
					}
				}

				// Normalize opacity (0..1)
				let opacity = parseFloat(wmOpacityRaw);
				if (Number.isNaN(opacity)) opacity = 0.6;
				if (opacity > 1) opacity = Math.min(1, opacity / 100);
				opacity = Math.max(0, Math.min(1, opacity));

				// Build transform request
				// Text watermarks are converted to SVG images and stored in R2
				// Then used like regular image watermarks

				const origin = new URL(request.url).origin;
				const mainR2Url = `${origin}/r2/${encodeURIComponent(mainKey)}`;

				const transformOptions: any = {
					cf: { image: {} },
					headers: { 'User-Agent': USER_AGENT },
				};

				// Add watermark overlay based on type
				if (watermarkType === 'text' && textSvgKey) {
					// Text watermark (converted to SVG image)
					const textWmUrl = `${origin}/r2/${encodeURIComponent(textSvgKey)}`;
					const grav = (wmGravity || 'center').toString().toLowerCase();
					const wmMarginDefault = 16;
					const margin = Math.max(wmMarginDefault, Math.round((mainDims?.w || 200) * 0.03));

					const drawObj: any = {
						url: textWmUrl,
						opacity: opacity,
						fit: 'contain',
					};

					// Optionally set width if main image dimensions are known
					if (mainDims?.w) {
						// Text watermarks typically use 30-50% of image width
						const textWmWidth = Math.round(mainDims.w * 0.4);
						drawObj.width = textWmWidth;
					}

					// Map gravity to positioning
					switch (grav) {
						case 'northwest':
						case 'top-left':
							drawObj.top = margin;
							drawObj.left = margin;
							break;
						case 'northeast':
						case 'top-right':
							drawObj.top = margin;
							drawObj.right = margin;
							break;
						case 'southwest':
						case 'bottom-left':
							drawObj.bottom = margin;
							drawObj.left = margin;
							break;
						case 'southeast':
						case 'bottom-right':
							drawObj.bottom = margin;
							drawObj.right = margin;
							break;
						case 'north':
						case 'top':
							drawObj.top = margin;
							break;
						case 'south':
						case 'bottom':
							drawObj.bottom = margin;
							break;
						case 'west':
						case 'left':
							drawObj.left = margin;
							break;
						case 'east':
						case 'right':
							drawObj.right = margin;
							break;
						case 'center':
						default:
							// Centered - no offsets
							break;
					}

					transformOptions.cf.image.draw = [drawObj];
					logInfo('Text watermark (PNG) configured', {
						text: wmText.trim(),
						gravity: grav,
						pngKey: textSvgKey,
						url: textWmUrl,
						size: wmTextSize,
						color: wmTextColor,
						opacity,
					});
				} else if (watermarkType === 'image' && watermarkKey) {
					// Image watermark overlay
					const useOriginalWmUrl = wmUrl && wmUrl.trim().length > 0;
					const finalWmUrl = useOriginalWmUrl ? wmUrl.trim() : `${origin}/r2/${encodeURIComponent(watermarkKey)}`;

					const wmMarginDefault = 8;
					const drawObj: any = {
						url: finalWmUrl,
						opacity,
					};

					if (overlayWidthPx) {
						drawObj.width = overlayWidthPx;
						drawObj.fit = 'contain';
					}

					// Map gravity to positioning
					const grav = (wmGravity || 'center').toString().toLowerCase();
					const margin = Math.max(wmMarginDefault, Math.round((mainDims?.w || 200) * 0.02));

					switch (grav) {
						case 'northwest':
						case 'top-left':
							drawObj.top = margin;
							drawObj.left = margin;
							break;
						case 'northeast':
						case 'top-right':
							drawObj.top = margin;
							drawObj.right = margin;
							break;
						case 'southwest':
						case 'bottom-left':
							drawObj.bottom = margin;
							drawObj.left = margin;
							break;
						case 'southeast':
						case 'bottom-right':
							drawObj.bottom = margin;
							drawObj.right = margin;
							break;
						case 'north':
						case 'top':
							drawObj.top = margin;
							break;
						case 'south':
						case 'bottom':
							drawObj.bottom = margin;
							break;
						case 'west':
						case 'left':
							drawObj.left = margin;
							break;
						case 'east':
						case 'right':
							drawObj.right = margin;
							break;
						case 'center':
						default:
							// Centered - no offsets
							break;
					}

					transformOptions.cf.image.draw = [drawObj];
					logInfo('Image watermark overlay configured', {
						gravity: grav,
						width: overlayWidthPx,
						opacity,
						watermarkUrl: finalWmUrl,
						usingOriginalUrl: useOriginalWmUrl,
					});
				}

				// Call Cloudflare image transform
				let transformed: Response;
				try {
					logInfo('Calling image transform', { url: mainR2Url });
					transformed = await fetch(mainR2Url, transformOptions);
				} catch (err) {
					logError('Transform network failure', err);
					return okJson({ error: 'Image transform failed' }, 500);
				}

				if (!transformed.ok) {
					logError('Transform returned error', {
						status: transformed.status,
						statusText: transformed.statusText,
					});
					return okJson({ error: 'Image transform failed' }, 500);
				}

				let outBuf: ArrayBuffer;
				try {
					outBuf = await transformed.arrayBuffer();
				} catch (err) {
					logError('Failed to read transform response', err);
					return okJson({ error: 'Failed to read transformed image' }, 500);
				}

				const outCt = transformed.headers.get('content-type') || mainCt || 'application/octet-stream';

				logInfo('Transform complete', {
					outputType: outCt,
					inputSize: mainBuf.byteLength,
					outputSize: outBuf.byteLength,
					compressionRatio: (mainBuf.byteLength / outBuf.byteLength).toFixed(2),
				});

				// Embed metadata
				try {
					if ((outCt.includes('jpeg') || outCt.includes('jpg')) && hasMetadata) {
						outBuf = insertExifIntoJpeg(outBuf, meta);
						logInfo('EXIF metadata inserted');
					} else if (outCt.includes('png') && Object.keys(meta).length) {
						outBuf = insertPngTextChunks(outBuf, meta);
						logInfo('PNG tEXt chunks inserted');
					} else if (outCt.includes('svg') && Object.keys(meta).length) {
						outBuf = insertSvgMetadata(outBuf, meta);
						logInfo('SVG metadata inserted');
					}
				} catch (err) {
					logError('Metadata insertion failed (non-fatal)', err);
				}

				// Return final image
				const headers = new Headers({ 'Content-Type': outCt });
				headers.set('Content-Disposition', `inline; filename="protected-${mainKey}"`);
				headers.set('Cache-Control', 'public, max-age=3600');

				const duration = Date.now() - startTime;
				logInfo('Request complete', {
					duration: `${duration}ms`,
					watermarkType,
					hasMetadata,
					finalSize: outBuf.byteLength,
				});

				return new Response(outBuf, { status: 200, headers });
			}

			// Health check
			if (request.method === 'GET') {
				return new Response(
					JSON.stringify({
						service: 'Image Protector Worker',
						version: '2.0',
						status: 'healthy',
						config: {
							maxFileSize: CONFIG.MAX_FILE_SIZE,
							maxMetadataSize: CONFIG.MAX_METADATA_SIZE,
							maxDimension: CONFIG.MAX_DIMENSION,
							fetchTimeout: CONFIG.FETCH_TIMEOUT,
						},
					}),
					{
						status: 200,
						headers: { 'content-type': 'application/json' },
					}
				);
			}

			return new Response('Method not allowed', { status: 405 });
		} catch (error: any) {
			const duration = Date.now() - startTime;
			logError('Unhandled error', { error, duration: `${duration}ms` });

			return okJson(
				{
					error: 'Internal server error',
					requestId: globalLogContext.requestId,
				},
				500
			);
		}
	},
};
