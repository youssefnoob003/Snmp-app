const trafficCharts = {};  // Store chart objects and data by interface index

function setupCharts(deviceId, interfaceIndexes) {
    const container = document.getElementById('chartContainer');
    container.innerHTML = '';  // Clear existing charts

    interfaceIndexes.forEach(intId => {
        const canvas = document.createElement('canvas');
        canvas.id = `trafficChart-${intId}`;
        canvas.style.display = 'none';
        canvas.width = container.offsetWidth;
        canvas.height = window.innerHeight * 0.4;
        container.appendChild(canvas);

        const ctx = canvas.getContext('2d');

        const timestamps = [];
        const inRates = [];
        const outRates = [];

        const chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: timestamps,
                datasets: [
                    {
                        label: 'Inbound Traffic',
                        data: inRates,
                        borderColor: '#6366f1',
                        backgroundColor: 'rgba(99, 102, 241, 0.2)',
                        fill: true,
                        tension: 0.3
                    },
                    {
                        label: 'Outbound Traffic',
                        data: outRates,
                        borderColor: '#8b5cf6',
                        backgroundColor: 'rgba(139, 92, 246, 0.2)',
                        fill: true,
                        tension: 0.3
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                scales: {
                    x: {
                        type: 'time',
                        time: {
                            unit: 'second',
                            stepSize: 10,
                            tooltipFormat: 'HH:mm:ss',
                            displayFormats: {
                                second: 'HH:mm:ss'
                            }
                        },
                        title: {
                            display: true,
                            text: 'Time',
                            font: { size: 12, weight: 'bold' }
                        },
                        ticks: {
                            font: { size: 10 },
                            maxRotation: 0,
                            maxTicksLimit: 5
                        },
                        grid: {
                            color: 'rgba(0,0,0,0.05)',
                            drawBorder: false
                        }
                    },
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Traffic Rate',
                            font: { size: 12, weight: 'bold' }
                        },
                        ticks: {
                            callback: value => formatBitRate(value),
                            font: { size: 10 },
                            maxTicksLimit: 10
                        },
                        grid: {
                            color: 'rgba(0,0,0,0.05)',
                            drawBorder: false
                        },
                        padding: { top: 40, bottom: 60 }
                    }
                },
                plugins: {
                    legend: {
                        position: 'top',
                        labels: { font: { size: 12, weight: 'bold' } }
                    },
                    tooltip: {
                        callbacks: {
                            label: context => `${context.dataset.label}: ${formatBitRate(context.parsed.y)}`
                        }
                    }
                }
            }
        });

        trafficCharts[intId] = chart;

        function updateChart() {
            fetch(`/get_graph_data/${deviceId}/${intId}`)
                .then(res => res.json())
                .then(data => {
                    if (data.error || !data.timestamps?.length) return;

                    timestamps.length = 0;
                    inRates.length = 0;
                    outRates.length = 0;

                    timestamps.push(...data.timestamps.map(t => new Date(t)));
                    inRates.push(...data.in_rates);
                    outRates.push(...data.out_rates);

                    // Calculate dynamic Y axis
                    const maxRate = Math.max(...inRates, ...outRates, 1);
                    const paddedMax = Math.ceil(maxRate * 1.2 / 100) * 100;
                    const minRate = Math.min(...inRates, ...outRates, 0);

                    chart.options.scales.y.max = paddedMax;
                    chart.options.scales.y.min = Math.max(minRate, 0);
                    chart.options.scales.y.ticks.stepSize = Math.max(Math.ceil((paddedMax - minRate) / 10), 50000);

                    chart.update();
                })
                .catch(err => console.error('Error updating chart:', err));
        }

        updateChart();
        setInterval(updateChart, 5000);

        window.addEventListener('resize', () => {
            canvas.width = canvas.parentElement.offsetWidth;
            canvas.height = window.innerHeight * 0.4;
            chart.resize();
        });
    });

    // Show the first chart initially
    if (interfaceIndexes.length > 0) {
        showChart(interfaceIndexes[0]);
    }
}

function showChart(intId) {
    Object.keys(trafficCharts).forEach(id => {
        const canvas = document.getElementById(`trafficChart-${id}`);
        if (canvas) {
            canvas.style.display = (id === intId) ? 'block' : 'none';
        }
    });
}

function formatBitRate(value) {
    if (value < 1000) return value.toFixed(1) + ' bps';
    if (value < 1000000) return (value / 1000).toFixed(1) + ' Kbps';
    return (value / 1000000).toFixed(1) + ' Mbps';
}
