# Application Requirements

## 1. Functional Requirements

### 1.1 User Identity Management
- Create, manage, share (public key + name only), and delete identities.
- Public keys shared via QR code or text.

### 1.2 Contacts Management
- Import contacts using QR code or text input of public key + name.
- List, search, rename, or delete contacts.

### 1.3 Photo Capture and Signing
- Capture photos using device camera or file picker.
- Compute SHA-256 hash treating QR code region as black.
- Sign hash with selected identity's private key.
- Generate QR code with hash, signature, and public key.
- Overlay QR code in configurable corner.

### 1.4 Photo Sharing
- Save signed photo locally and provide share options.

### 1.5 Photo Verification
- Accept photo via file picker or URL.
- Extract QR code and verify signature against hash.

## 2. Non-Functional Requirements
- Private keys never leave device; use secure storage.
- Signing and QR generation should complete in under 500 ms on typical devices.
- Emphasize client-side operations for low-cost hosting.
- Single codebase targeting web, iOS, and Android.

## 3. Data Model (Client-Side)

| Entity | Fields |
| --- | --- |
| Identity | `id`, `name`, `publicKey`, `privateKey`, `createdAt` |
| Contact | `id`, `name`, `publicKey`, `notes?` |
| PhotoMeta | `id`, `imageURI`, `hash`, `signature`, `publicKey`, `qrCorner`, `createdAt` |

## 4. API Design (Backend)

| Endpoint | Method | Description |
| --- | --- | --- |
| `/photos` | POST | Upload signed photo (optional). Returns URL or ID. |
| `/photos/{id}` | GET | Retrieve photo metadata and file URL. |
| `/contacts/{publicKey}` | GET | Lookup public profile by key (optional). |
| `/hooks/agent` | POST | Webhook for AI agent events (photo signed, verified, etc.). |

## 5. User Interface Outline

1. Identity screen: list and manage identities.
2. Contacts screen: import, list, and manage contacts.
3. Camera/signer screen: capture, sign, and overlay QR code.
4. Gallery/history: view signed photos and metadata.
5. Verify screen: select photo or URL and display verification results.

## 6. Framework and Tooling

- **Frontend:** Expo (React Native + web). Use TypeScript, `expo-camera`, `expo-secure-store`, `noble-ed25519`, `jsqr`/`zxing`, `react-native-qrcode-svg`, `expo-sharing`.
- **Backend:** Supabase or Firebase for storage, serverless functions, and optional profile lookup.

## 7. Hosting Suggestions

| Component | Provider | Notes |
| --- | --- | --- |
| Web app | Vercel or Netlify | Free plans with auto-deploy from GitHub. |
| Mobile app | Expo OTA + EAS | Free OTA updates, low-cost build service. |
| Storage/DB | Supabase or Firebase | Generous free tiers. |
| AI hooks | Serverless functions or Cloudflare Workers | Optional integration for agents. |

## 8. Development Workflow

1. Initialize monorepo with Expo.
2. Implement cryptographic utilities using `webcrypto` or `noble-ed25519`.
3. Build identity and contact management screens.
4. Implement photo capture, hashing, signing, and QR overlay.
5. Add sharing and verification screens.
6. Integrate optional backend for photo upload or AI webhooks.
7. Test on devices and web.
8. Deploy web via Vercel and publish mobile via Expo and app stores.

## 9. Security Considerations

- Use HTTPS for web.
- Store private keys in secure storage; never transmit to backend.
- Validate imported contacts to prevent malformed keys.
- Treat QR code region as opaque when hashing.

