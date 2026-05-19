// 迷你日历渲染
document.addEventListener('DOMContentLoaded', () => {
  const cal = document.getElementById('miniCalendar');
  if (!cal) return;

  const year  = parseInt(cal.dataset.year);
  const month = parseInt(cal.dataset.month);
  const hasEntries = new Set((cal.dataset.hasEntries || '').split(',').filter(Boolean));
  const today = new Date().toISOString().slice(0, 10);

  const firstDay = new Date(year, month - 1, 1).getDay();
  const daysInMonth = new Date(year, month, 0).getDate();
  const monthNames = ['一月','二月','三月','四月','五月','六月','七月','八月','九月','十月','十一月','十二月'];
  const dayNames = ['日','一','二','三','四','五','六'];

  let html = `<div class="cal-header"><span>${year}年 ${monthNames[month-1]}</span></div>`;
  html += '<div class="cal-grid">';
  dayNames.forEach(d => { html += `<div class="cal-day-name">${d}</div>`; });

  // Empty cells before first day
  for (let i = 0; i < firstDay; i++) {
    html += '<div class="cal-day other-month"></div>';
  }

  for (let d = 1; d <= daysInMonth; d++) {
    const dateStr = `${year}-${String(month).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
    let cls = 'cal-day';
    if (hasEntries.has(dateStr)) cls += ' has-entry';
    if (dateStr === today) cls += ' today';
    html += `<div class="${cls}" title="${dateStr}">${d}</div>`;
  }

  html += '</div>';
  cal.innerHTML = html;
});

// Flash 消息自动消失
setTimeout(() => {
  document.querySelectorAll('.flash').forEach(el => {
    el.style.transition = 'opacity .5s';
    el.style.opacity = '0';
    setTimeout(() => el.remove(), 500);
  });
}, 3000);
