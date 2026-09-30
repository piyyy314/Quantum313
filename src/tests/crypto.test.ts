import { describe, test, expect } from 'vitest';
import CryptoJS from 'crypto-js';

describe('Aegis Secure Cryptographic Handshake and Forensics Envelope Integrity', () => {
  const samplePayload = {
    meta: {
      suite: "Aegis Unified Security Suite",
      version: "v2.5.0-Enterprise",
      exported_by: "baalbek.313@gmail.com",
      system_time: new Date().toISOString()
    },
    ebpf_kernel_execution_logs: [
      {
        event_id: "ebpf-1011",
        executable_name: "svchost.exe",
        invoked_system_call: "sys_execve",
        governing_sandbox_action: "blocked"
      }
    ]
  };

  const plainTextString = JSON.stringify(samplePayload, null, 2);
  const correctPassphrase = "SuperSecureShieldKey123!";
  const incorrectPassphrase = "WrongPassword999";

  test('Symmetric encryption should output a valid cipher string', () => {
    const ciphertext = CryptoJS.AES.encrypt(plainTextString, correctPassphrase).toString();
    expect(ciphertext).toBeDefined();
    expect(ciphertext.length).toBeGreaterThan(0);
    expect(ciphertext).not.toEqual(plainTextString);
  });

  test('Symmetric decryption with the CORRECT passphrase should recover the original plaintext exactly', () => {
    // Encrypt
    const ciphertext = CryptoJS.AES.encrypt(plainTextString, correctPassphrase).toString();
    
    // Decrypt
    const decryptedBytes = CryptoJS.AES.decrypt(ciphertext, correctPassphrase);
    const decryptedText = decryptedBytes.toString(CryptoJS.enc.Utf8);
    
    expect(decryptedText).toEqual(plainTextString);
    const parsed = JSON.parse(decryptedText);
    expect(parsed.meta.suite).toEqual("Aegis Unified Security Suite");
  });

  test('Symmetric decryption with an INCORRECT passphrase should fail to output valid UTF-8 plaintext', () => {
    // Encrypt
    const ciphertext = CryptoJS.AES.encrypt(plainTextString, correctPassphrase).toString();
    
    // Decrypt with bad passphrase
    const decryptedBytes = CryptoJS.AES.decrypt(ciphertext, incorrectPassphrase);
    
    // Try to convert to UTF-8. Typically will return an empty string or corrupt output.
    let decryptedText = "";
    try {
      decryptedText = decryptedBytes.toString(CryptoJS.enc.Utf8);
    } catch {
      decryptedText = "";
    }
    
    expect(decryptedText).not.toEqual(plainTextString);
  });

  test('Container block envelopes should parse correctly', () => {
    const ciphertext = CryptoJS.AES.encrypt(plainTextString, correctPassphrase).toString();
    const formattedContainer = `-----BEGIN AEGIS SECURE FORENSICS CONTAINER-----\n${ciphertext}\n-----END AEGIS SECURE FORENSICS CONTAINER-----`;

    // Extract inside test
    expect(formattedContainer).toContain('-----BEGIN AEGIS SECURE FORENSICS CONTAINER-----');
    expect(formattedContainer).toContain('-----END AEGIS SECURE FORENSICS CONTAINER-----');

    let extractedCipher = formattedContainer
      .replace('-----BEGIN AEGIS SECURE FORENSICS CONTAINER-----', '')
      .replace('-----END AEGIS SECURE FORENSICS CONTAINER-----', '')
      .trim();

    expect(extractedCipher).toEqual(ciphertext);

    const decryptedBytes = CryptoJS.AES.decrypt(extractedCipher, correctPassphrase);
    const decryptedText = decryptedBytes.toString(CryptoJS.enc.Utf8);
    expect(decryptedText).toEqual(plainTextString);
  });
});
