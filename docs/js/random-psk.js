// docs/js/random-psk.js

function randomString(len = 22) {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const charsLen = chars.length;

    const max = Math.floor(256 / charsLen) * charsLen;
    let result = '';

    while (result.length < len) {
        const buf = new Uint8Array(len);
        crypto.getRandomValues(buf);

        for (let i = 0; i < buf.length && result.length < len; i++) {
            if (buf[i] < max) {
                result += chars[buf[i] % charsLen];
            }
        }
    }
    return result;
}

document$.subscribe(function() {
    // 1. 生成一个随机的高强度 PSK
    const randomKey = randomString();
    const simpleKey = randomString(16);

    // 2. 找到所有的代码块
    const codeBlocks = document.querySelectorAll('code');

    codeBlocks.forEach(block => {
        // 检查代码块里是否有 mysecret123
        if (block.textContent.includes('mysecret123')) {
            // 3. 执行替换
            // 注意：这里使用 innerHTML 替换，以保持原有的高亮格式。
            // 只要 mysecret123 是个完整的单词，通常不会被高亮插件切割，可以直接替换。
            const regex = /mysecret123/g;
            const replacement = `<span title="随机示例Key">${randomKey}</span>`;
            block.innerHTML = block.innerHTML.replace(regex, replacement);
        }
        if (block.textContent.includes('simplekey123')) {
            const regex2 = /simplekey123/g;
            const replacement2 = `<span title="随机示例Key">${simpleKey}</span>`;
            block.innerHTML = block.innerHTML.replace(regex2, replacement2);
        }
    });
});