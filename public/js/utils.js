// public/js/utils.js

export const textEncoder = new TextEncoder();
export const textDecoder = new TextDecoder();

export function bufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

export function base64ToBuffer(str) {
    return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

/**
 * Extract content from a File input
 * @param {HTMLInputElement} inputElement 
 * @returns {Promise<string>}
 */
export async function extractFileContent(inputElement) {
    const file = inputElement.files[0];
    if (!file) return '';
    const text = await file.text();
    inputElement.value = '';
    return text.trim();
}

/**
 * Simple debounce function
 */
export function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}
