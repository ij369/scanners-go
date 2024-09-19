document.addEventListener('DOMContentLoaded', function () {
    // 检查是否在配置页面
    const isConfigPage = window.location.pathname.startsWith('/config');

    if (isConfigPage) {
        // 加载配置
        fetch('/api/config')
            .then(response => response.json())
            .then(data => {
                document.getElementById('forwardURL').value = data.forwardURL;
                document.getElementById('resetInterval').value = data.resetInterval;
                document.getElementById('autoOpenPage').checked = data.autoOpenPage;
                document.getElementById('showSpecialChars').checked = data.showSpecialChars;
                document.getElementById('showConsole').checked = data.showConsole;
                document.getElementById('startOnBoot').checked = data.startOnBoot;
                document.getElementById('endSuffix').value = data.endSuffix || 'ENTER';
                document.getElementById('outputRegex').value = data.outputRegex || '';
            });

        // 提交表单
        document.getElementById('configForm').addEventListener('submit', function (e) {
            e.preventDefault();
            const formData = {
                forwardURL: document.getElementById('forwardURL').value,
                resetInterval: parseInt(document.getElementById('resetInterval').value),
                autoOpenPage: document.getElementById('autoOpenPage').checked,
                showSpecialChars: document.getElementById('showSpecialChars').checked,
                showConsole: document.getElementById('showConsole').checked,
                startOnBoot: document.getElementById('startOnBoot').checked,
                endSuffix: document.getElementById('endSuffix').value,
                outputRegex: document.getElementById('outputRegex').value,
            };

            fetch('/api/config', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(formData),
            })
                .then(response => {
                    if (response.ok) {
                        Swal.fire({
                            icon: 'success',
                            title: '配置已保存',
                            showConfirmButton: false,
                            toast: true,
                            position: 'top-end',
                            timer: 1500
                        });
                    } else {
                        Swal.fire({
                            icon: 'error',
                            title: '保存配置失败',
                            showConfirmButton: false,
                            toast: true,
                            position: 'top-end',
                            timer: 3000
                        });
                    }
                })
                .catch((error) => {
                    console.error('Error:', error);
                    Swal.fire({
                        icon: 'error',
                        title: '保存配置时发生错误',
                        showConfirmButton: false,
                        timer: 3000,
                        toast: true,
                        position: 'top-end',
                    });
                });
        });
    }

    // WebSocket 连接（在主页和配置页都需要）
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const socket = new WebSocket(protocol + '//' + window.location.host + '/ws');
    const scanResults = document.getElementById('scanResults');

    if (scanResults) {
        const maxResults = 10;

        socket.onmessage = function (event) {
            const li = document.createElement('li');
            li.textContent = event.data;
            scanResults.insertBefore(li, scanResults.firstChild);

            // 保持最多显示 10 条结果
            while (scanResults.children.length > maxResults) {
                scanResults.removeChild(scanResults.lastChild);
            }
        };
    }

    socket.onerror = function (error) {
        console.error('WebSocket 错误:', error);
    };

    socket.onclose = function () {
        console.log('WebSocket 连接已关闭');
        Swal.fire({
            icon: 'error',
            title: 'WebSocket 连接已关闭',
        });
    };
});