document.addEventListener("DOMContentLoaded", function() {
    // === 配置项 ===
    const targetKeyword = "server-ip";      // 原始占位符
    const wrapperClass = "dynamic-var-ip";  // 注入的标签 Class
    
    // === 第一步：初始化（占坑） ===
    // 这个步骤页面加载后只执行一次！
    const codeBlocks = document.querySelectorAll(".md-typeset code");
    
    codeBlocks.forEach(block => {
        // 只有包含关键词才处理，且避免重复处理（防止脚本跑两次）
        if (block.innerHTML.includes(targetKeyword) && !block.innerHTML.includes(wrapperClass)) {
            // 使用正则全局替换，把文字变成 <span> 标签
            // 这里的逻辑是：把 "server-ip" 变成 <span class="dynamic-var-ip">server-ip</span>
            const regex = new RegExp(targetKeyword, "g");
            block.innerHTML = block.innerHTML.replace(regex, `<span class="${wrapperClass}">${targetKeyword}</span>`);
        }
    });

    // === 第二步：定义更新函数（填坑） ===
    // 这个函数会暴露给 window，供 HTML 中的 input 调用
    let timeout = null;
    window.updateServerIP = function(input) {
        // 如果用户清空了输入框，就恢复成默认的 "server-ip"
        const newValue = input.value.trim() === "" ? targetKeyword : input.value;

        // 防抖逻辑：用户停止打字 0.5 秒后才更新，避免页面频繁闪烁
        clearTimeout(timeout);
        timeout = setTimeout(() => {
            // 关键点：我们不是找“字”，而是找我们刚才埋下的“Class”
            const targets = document.querySelectorAll(`.${wrapperClass}`);
            
            targets.forEach(span => {
                // 直接替换 span 标签里的文字
                span.textContent = newValue;
                
                // 加一个小动画（闪一下黄色），提示用户这里变了
                span.style.transition = "background-color 0.3s";
                span.style.backgroundColor = "#ffeb3b"; // 黄色高亮
                
                setTimeout(() => {
                    span.style.backgroundColor = "transparent";
                }, 500);
            });
            
        }, 500); // 延迟 500ms
    };
});