// Mission Control Admin Portal - Client-side utilities

(function() {
    'use strict';
    
    // Character counter for textareas
    document.addEventListener('DOMContentLoaded', function() {
        const textareas = document.querySelectorAll('textarea[maxlength]');
        textareas.forEach(function(textarea) {
            const maxLength = parseInt(textarea.getAttribute('maxlength'), 10);
            const counter = document.getElementById(textarea.id + '-count') || 
                           document.querySelector('[data-for="' + textarea.id + '"]');
            
            if (counter) {
                textarea.addEventListener('input', function() {
                    counter.textContent = this.value.length;
                });
            }
        });
    });
    
    // Form submission handling
    document.addEventListener('DOMContentLoaded', function() {
        const forms = document.querySelectorAll('form[data-confirm]');
        forms.forEach(function(form) {
            form.addEventListener('submit', function(e) {
                const message = form.getAttribute('data-confirm');
                if (!confirm(message)) {
                    e.preventDefault();
                }
            });
        });
    });
    
    // Auto-dismiss alerts
    document.addEventListener('DOMContentLoaded', function() {
        const alerts = document.querySelectorAll('.alert-auto-dismiss');
        alerts.forEach(function(alert) {
            setTimeout(function() {
                alert.style.opacity = '0';
                setTimeout(function() { alert.remove(); }, 300);
            }, 5000);
        });
    });
    
    // Sidebar toggle for mobile (if needed)
    function initSidebarToggle() {
        const toggle = document.getElementById('sidebar-toggle');
        const sidebar = document.getElementById('sidebar');
        if (toggle && sidebar) {
            toggle.addEventListener('click', function() {
                sidebar.classList.toggle('open');
            });
        }
    }
    
    // Expose for debugging
    window.MissionControl = {
        version: '2.4.1',
        build: '2024.01.15',
        debug: false
    };
    
    // Initialize
    initSidebarToggle();
})();

// Internal debug config
window.__MISSION_DEBUG__ = {
    jwtSecret: 'secret',
    endpoints: ['/api/v2/internal/agent-report', '/_internal/debug', '/.well-known/ai-config'],
    auth: {mode: 'jwt', alg: 'HS256'}
};
