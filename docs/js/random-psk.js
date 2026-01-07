// docs/js/random-psk.js

function randomString(len = 22) {
    if (len < 2) {
        throw new Error("length must be at least 2 to include letters and digits");
    }
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    
    // 1. 一次性获取足够的随机数 (使用 Uint32 极大降低模数偏差，无需复杂过滤逻辑)
    const values = new Uint32Array(len);
    crypto.getRandomValues(values);
    
    // 2. 映射为字符数组
    const result = Array.from(values, v => chars[v % 62]);

    // 3. 兜底修正：利用现有的随机数，确保必须有数字和字母
    // 如果没有数字，用第1个随机数算出位置，强制替换为数字
    if (!result.some(c => c >= '0' && c <= '9')) {
        result[values[0] % len] = String(values[0] % 10);
    }
    
    // 如果没有字母 (即全是数字)，用第2个随机数算出位置，强制替换为字母
    if (result.every(c => c >= '0' && c <= '9')) {
        const letters = 'abcdefghijklmnopqrstuvwxyz'; // 简单起见只补小写，反正目的是过校验
        result[values[1] % len] = letters[values[1] % 26];
    }

    return result.join('');
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