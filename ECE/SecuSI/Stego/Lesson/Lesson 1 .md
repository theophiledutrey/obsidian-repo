
## 1  Definition and Purpose
- **Steganography** = hiding secret data inside a medium without raising suspicion.  
- Unlike cryptography, it does not attract attention since the carrier appears normal.  
- Mediums can include: images, audio, video, documents, or even network traffic.

---

## 2  Domains of Insertion

| Domain              | Concept                                                                                     | Robustness |
| ------------------- | ------------------------------------------------------------------------------------------- | ---------- |
| **Spatial domain**  | Hide data in pixel values directly (e.g., **Least Significant Bit** modifications).          | Low        |
| **Frequency domain**| Hide data in transformed frequency coefficients (DFT, DCT, DWT).                             | High       |

- **Spatial** → easy to implement, but vulnerable to compression & editing.  
- **Frequency** → harder to break, more robust against compression and cropping.  

---

## 3  Spatial Domain Example – LSB

### 3.1 How it works
- Modify the **Least Significant Bit (LSB)** of each pixel.  
- Human eyes barely perceive these changes.  
- Computationally cheap (no preprocessing needed).

### 3.2 Example
Container pixel (10,10):  
```
RUID = 174, 176, 191   -> binary (...10101110, ...)
```
Secret pixel:  
```
160, 163, 154 -> binary (...10100000, ...)
```
Final stego pixel:  
```
170, 186, 185
```

👉 In CTFs, **binwalk** or **strings** won’t help; you need tools like `zsteg`, `stegsolve`, or custom scripts.

---

## 4  GIF Steganography (EzStego)

### 4.1 Principle
- GIF89a format → palette of 256 colors.  
- EzStego creates a **sorted palette** where adjacent colors look almost identical.  
- Each color index encodes a **binary value**.

### 4.2 Process
1. Sort palette → assign binary indexes (`000`, `001`, …).  
2. Hide message bits in the **LSB of the palette index**.  
3. Extraction = rebuild sorted palette + read LSB of each pixel’s index.

👉 This is often used in **older stego challenges** where palette swapping hides messages.

---

## 5  Frequency Domain – JPEG Compression

### 5.1 DCT Principle
- JPEG compression relies on **DCT (Discrete Cosine Transform)**:  
  - Split image into **8×8 blocks**.  
  - Convert pixel values → frequency coefficients.  
  - Low frequencies (top-left of DCT matrix) = essential details.  
  - High frequencies (bottom-right) = fine details, often discarded.  

### 5.2 Importance
- Human eye is more sensitive to **low frequencies** than high ones.  
- Dropping 50% of high frequencies = only ~5% info loss.  

### 5.3 Compression Steps
1. Split into 8×8 blocks.  
2. Apply DCT.  
3. Quantize (drop less important coefficients).  
4. Linearize (ZigZag order).  
5. Compress (entropy coding).  

👉 In CTFs, if data is hidden in DCT coefficients, tools like **stegbreak** or manual DCT parsing may be needed.

---

## 6  Malicious Uses

- Malware can hide payloads in images.  
- **APT10 – Backdoor.Stegmap (2022)**:  
  - Fetch image from GitHub containing XOR-encrypted payload.  
  - Decrypt and execute (files, registry, processes).  
  - Advantage: hosted on trusted sites → bypasses C2 detection.  

---

## 7  Watermarking

### 7.1 Goal
- Protect intellectual property and trace leaks.  

### 7.2 Types
- **Visible**: watermark text/logo over image.  
- **Invisible**: hidden metadata or pixel modifications.  

### 7.3 Use Cases
- Track data breaches.  
- Fight counterfeiting.  

Types of watermark:  
- **Fragile** → breaks easily if altered.  
- **Robust** → survives compression & transformations.

---

## 8  Steganalysis

- The art of **detecting hidden data**.  
- Analogous to cryptanalysis in cryptography.  
- Difficult because:  
  - Many different mediums.  
  - Many insertion algorithms.  
  - Hidden data introduces very low distortion.  

👉 Techniques:  
- Statistical analysis of noise.  
- Comparison with expected image properties.  

---

## 9  Preventing Steganography

- Compare **statistical properties** of normal vs suspect files.  
- Add **noise** or recompress files to break hidden channels.  
- To block covert channels entirely:  
  - Intercept all comms.  
  - Transform or recompress before delivery.  

---

## 10  Document Marking

- Used to **tag documents** and detect leaks:  
  - Simple: headers/footers (e.g., “Confidential”).  
  - Complex: hidden metadata (XML properties, PDF keys).  
- Example:  
  - Office Open XML (post-2007) = zipped XML files → tags inserted inside.  

---

## 11  Data Exfiltration Detection

- Infrastructure needed:  
  - Web proxy, mail proxy.  
  - USB DLP protection.  
  - Detection of tag removal attempts.  
- Problem: encrypted flows.  
  - Need to decrypt streams → **breaks secure channels**.  
  - Data is exposed on the proxy in plaintext.

---

## 12  Decryption of Flows

- To inspect HTTPS traffic:  
  - Proxy intercepts connection.  
  - Client trusts proxy’s custom certificate.  
  - Proxy decrypts, inspects, re-encrypts to final server.  

👉 This is **SSL inspection** – widely used in enterprises.

---

## 13  Conclusion

- Steganography = covert communication technique.  
- Strength: invisible to antivirus/IDS.  
- Weakness: capacity decreases with robustness/invisibility.  
- Applications:  
  - Malicious (payload hiding, malware).  
  - Legitimate (copyright watermarking, tracing leaks).  

---

## ✅ CTF Tips
- Check for LSB stego in PNG/BMP.  
- Inspect GIF palettes.  
- Analyze JPEG DCT coefficients.  
- Don’t forget audio/video stego challenges (spectrograms, phase coding).  