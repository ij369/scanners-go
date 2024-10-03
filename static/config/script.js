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

                document.getElementById('actionPrefix').value = data.actions.prefix || '';
                document.getElementById('actionSuffix').value = data.actions.suffix || '';
                document.getElementById('actionCommand').value = data.actions.command || '';
                document.getElementById('actionArguments').value = data.actions.arguments ? data.actions.arguments.join('\n') : '';
                document.getElementById('actionEnable').checked = data.actions.command !== '';
                document.getElementById('actionFieldset').disabled = !document.getElementById('actionEnable').checked;
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

            if (document.getElementById('actionEnable').checked) {
                formData.actions = {
                    prefix: document.getElementById('actionPrefix').value,
                    suffix: document.getElementById('actionSuffix').value,
                    command: document.getElementById('actionCommand').value,
                    arguments: document.getElementById('actionArguments').value
                        .split('\n')
                        .map(arg => arg.trim())
                        .filter(arg => arg !== ''),
                    dataIndex: document.getElementById('actionArguments').value
                        .split('\n')
                        .findIndex(arg => arg.includes('{data}')),
                };
            }

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
    function connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const socket = new WebSocket(protocol + '//' + window.location.host + '/ws');
        const scanResults = document.getElementById('scanResults');

        socket.onmessage = function (event) {
            const li = document.createElement('li');
            li.textContent = event.data;
            Swal.fire({
                title: event.data,
                icon: 'success',
                showConfirmButton: false,
                toast: true,
                position: 'top-end',
                timerProgressBar: event.data !== 'CONNECTED',
                timer: 3000
            });
            scanResults.insertBefore(li, scanResults.firstChild);

            // 保持最多显示 10 条结果
            while (scanResults.children.length > 10) {
                scanResults.removeChild(scanResults.lastChild);
            }
        };

        socket.onerror = function (error) {
            console.error('WebSocket 错误:', error);
        };

        socket.onclose = function () {
            console.debug('WebSocket 连接已关闭');
            Swal.fire({
                icon: 'error',
                title: 'WebSocket 连接已关闭',
                timer: 5000,
                toast: true,
                showConfirmButton: false,
                position: 'top-end',
            });

            // 每隔 5 秒尝试重新连接
            const retryInterval = setInterval(() => {
                console.debug('尝试重新连接 WebSocket...');
                const newSocket = new WebSocket(protocol + '//' + window.location.host + '/ws');

                newSocket.onopen = function () {
                    console.log('WebSocket 重新连接成功');
                    Swal.fire({
                        icon: 'success',
                        title: 'WebSocket 重新连接成功',
                        showConfirmButton: false,
                        toast: true,
                        position: 'top-end',
                        timer: 3000
                    });
                    clearInterval(retryInterval);
                    // 重新绑定事件处理程序
                    newSocket.onmessage = socket.onmessage;
                    newSocket.onerror = socket.onerror;
                    newSocket.onclose = socket.onclose;
                };

                newSocket.onerror = function (error) {
                    console.error('WebSocket 重新连接错误:', error);
                    Swal.fire({
                        icon: 'error',
                        title: 'WebSocket 连接已关闭, 正在尝试连接...',
                        timer: 5000,
                        toast: true,
                        showConfirmButton: false,
                        position: 'top-end',
                    });
                };
            }, 5000);
        };
    }

    connectWebSocket();
});