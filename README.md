# Image Protector – Cloudflare Workers

Minimal Cloudflare Workers project that embeds EXIF metadata into JPEGs and optionally applies a resized watermark using Cloudflare [Image Transformations](https://developers.cloudflare.com/images/transform-images/transform-via-workers/).

## Features

- Upload main image (file or public URL).
- Optionally upload watermark (file or public URL). Watermark is resized to avoid covering the whole image.
- Embed EXIF tags into **JPEG** outputs (ImageDescription, Artist, Copyright, plus JSON fallback).
- Deterministic R2 storage keys using Web Crypto SHA-256.
- Uses Cloudflare Image Transform `cf.image.draw` for watermarking.
- Detailed logging for debugging.

## Setup and Deployment

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/DavidJKTofan/cf-workers-exif-images)

## API

- `POST /process` — multipart/form-data or fields:

  - `main_file` (File) or `main_url` (string) — main image.
  - `watermark_file` (File) or `watermark_url` (string) — optional watermark.
  - `metadata_json` (string) or `meta_<key>` fields — metadata (must be provided only for JPEG main images).
  - `wm_size` — watermark size (e.g. `20p` or `150` pixels). Default `20p`.
  - `wm_opacity` — opacity (0..1 or percent like `60`). Default `60`.
  - `wm_gravity` — gravity (e.g. `center`, `northwest`).

Response: transformed image (inline). Errors returned as JSON.

## Notes

- EXIF embedding only supported for JPEG main images; the worker returns `400` if metadata is provided for non-JPEG mains.
- The EXIF implementation is intentionally minimal (common ASCII tags and JSON fallback). For full EXIF support use a dedicated metadata tool during a build step.
- No third-party libraries are used.

---

# Disclaimer

This project is intended for educational and personal use. You are responsible for implementing appropriate security and operational measures for production deployments. Always audit and test before production rollout.

The domains might not work always, or not anymore at all in the near future.
