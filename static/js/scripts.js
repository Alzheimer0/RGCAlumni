// .static/js/scripts.js

document.addEventListener("DOMContentLoaded", function () {
    // Profile form validation
    const profileForm = document.querySelector("form.profile-form");

    if (profileForm) {
        profileForm.addEventListener("submit", function (event) {
            let valid = true;
            const name = document.getElementById("name");
            const graduationYear = document.getElementById("graduation_year");
            const industry = document.getElementById("industry");
            const contactDetails = document.getElementById("contact_details");

            // Simple validation checks
            if (!name.value.trim()) {
                valid = false;
                alert("Name is required.");
                name.focus();
            } else if (!graduationYear.value.trim() || isNaN(graduationYear.value) || graduationYear.value < 1900 || graduationYear.value > new Date().getFullYear()) {
                valid = false;
                alert("Please enter a valid graduation year.");
                graduationYear.focus();
            } else if (!industry.value.trim()) {
                valid = false;
                alert("Industry is required.");
                industry.focus();
            } else if (!contactDetails.value.trim()) {
                valid = false;
                alert("Contact details are required.");
                contactDetails.focus();
            }

            if (!valid) {
                event.preventDefault(); // Prevent form submission if validation fails
            }
        });
    }

    // Event form validation
    const eventForm = document.querySelector("form.event-form");

    if (eventForm) {
        eventForm.addEventListener("submit", function (event) {
            let valid = true;
            const title = document.getElementById("title");
            const date = document.getElementById("date");
            const location = document.getElementById("location");
            const description = document.getElementById("description");

            // Simple validation checks
            if (!title.value.trim()) {
                valid = false;
                alert("Title is required.");
                title.focus();
            } else if (!date.value.trim()) {
                valid = false;
                alert("Date is required.");
                date.focus();
            } else if (!location.value.trim()) {
                valid = false;
                alert("Location is required.");
                location.focus();
            } else if (!description.value.trim()) {
                valid = false;
                alert("Description is required.");
                description.focus();
            }

            if (!valid) {
                event.preventDefault(); // Prevent form submission if validation fails
            }
        });
    }

    // Discussion form validation
    const discussionForm = document.querySelector("form.discussion-form");

    if (discussionForm) {
        discussionForm.addEventListener("submit", function (event) {
            let valid = true;
            const topic = document.getElementById("topic");
            const content = document.getElementById("content");
            const category = document.getElementById("category");

            // Simple validation checks
            if (!topic.value.trim()) {
                valid = false;
                alert("Topic is required.");
                topic.focus();
            } else if (!content.value.trim()) {
                valid = false;
                alert("Content is required.");
                content.focus();
            } else if (!category.value.trim()) {
                valid = false;
                alert("Category is required.");
                category.focus();
            }

            if (!valid) {
                event.preventDefault(); // Prevent form submission if validation fails
            }
        });
    }

    // Job post form validation
    const jobForm = document.querySelector("form.job-form");

    if (jobForm) {
        jobForm.addEventListener("submit", function (event) {
            let valid = true;
            const title = document.getElementById("title");
            const description = document.getElementById("description");
            const company = document.getElementById("company");
            const location = document.getElementById("location");

            // Simple validation checks
            if (!title.value.trim()) {
                valid = false;
                alert("Title is required.");
                title.focus();
            } else if (!description.value.trim()) {
                valid = false;
                alert("Description is required.");
                description.focus();
            } else if (!company.value.trim()) {
                valid = false;
                alert("Company is required.");
                company.focus();
            } else if (!location.value.trim()) {
                valid = false;
                alert("Location is required.");
                location.focus();
            }

            if (!valid) {
                event.preventDefault(); // Prevent form submission if validation fails
            }
        });
    }

    // Mentorship form validation
    const mentorshipForm = document.querySelector("form.mentorship-form");

    if (mentorshipForm) {
        mentorshipForm.addEventListener("submit", function (event) {
            let valid = true;
            const mentorName = document.getElementById("mentor_name");
            const menteeName = document.getElementById("mentee_name");
            const details = document.getElementById("details");
            const contactInfo = document.getElementById("contact_info");

            // Simple validation checks
            if (!mentorName.value.trim()) {
                valid = false;
                alert("Mentor name is required.");
                mentorName.focus();
            } else if (!menteeName.value.trim()) {
                valid = false;
                alert("Mentee name is required.");
                menteeName.focus();
            } else if (!details.value.trim()) {
                valid = false;
                alert("Details are required.");
                details.focus();
            } else if (!contactInfo.value.trim()) {
                valid = false;
                alert("Contact information is required.");
                contactInfo.focus();
            }

            if (!valid) {
                event.preventDefault(); // Prevent form submission if validation fails
            }
        });
    }

});

document.addEventListener("DOMContentLoaded", function () {
    // Hide flash messages after 5 seconds
    const flashes = document.querySelectorAll(".alert");
    flashes.forEach(function (alert) {
        setTimeout(function () {
            alert.style.display = "none";
        }, 5000); // 5000 milliseconds = 5 seconds
    });
});

// Enhanced Logo System Functionality
document.addEventListener("DOMContentLoaded", function () {
    // Initialize logo system
    initializeLogoSystem();
    
    // Setup logo preloading
    preloadLogos();
    
    // Setup keyboard accessibility
    setupLogoKeyboardAccess();
    
    // Setup logo error handling
    setupLogoErrorHandling();
});

// Initialize the logo system
function initializeLogoSystem() {
    const logoWrapper = document.querySelector('.logo-wrapper');
    if (logoWrapper) {
        logoWrapper.classList.add('logo-loaded');
        
        // Load user logo preference from localStorage
        const savedLogoPreference = localStorage.getItem('logoPreference');
        if (savedLogoPreference === 'secondary') {
            const primaryLogo = document.getElementById('primary-logo');
            const secondaryLogo = document.getElementById('secondary-logo');
            if (primaryLogo && secondaryLogo) {
                primaryLogo.classList.add('d-none');
                secondaryLogo.classList.remove('d-none');
            }
        }
    }
}

// Enhanced logo toggle function with analytics
function toggleLogo() {
    const primaryLogo = document.getElementById('primary-logo');
    const secondaryLogo = document.getElementById('secondary-logo');
    const logoWrapper = document.querySelector('.logo-wrapper');
    
    if (!primaryLogo || !secondaryLogo || !logoWrapper) {
        console.warn('Logo elements not found');
        return;
    }
    
    // Add transition effect
    logoWrapper.classList.add('logo-switching');
    
    // Add haptic feedback for mobile devices
    if (navigator.vibrate) {
        navigator.vibrate(50);
    }
    
    setTimeout(() => {
        let switchType = 'unknown';
        let newLogoType = 'primary';
        
        if (primaryLogo.classList.contains('d-none')) {
            primaryLogo.classList.remove('d-none');
            secondaryLogo.classList.add('d-none');
            switchType = 'to_primary';
            newLogoType = 'primary';
        } else {
            primaryLogo.classList.add('d-none');
            secondaryLogo.classList.remove('d-none');
            switchType = 'to_secondary';
            newLogoType = 'secondary';
        }
        
        logoWrapper.classList.remove('logo-switching');
        
        // Save user preference
        localStorage.setItem('logoPreference', newLogoType);
        
        // Track the logo switch for analytics
        trackLogoSwitch(switchType);
        
        // Announce change for screen readers
        announceLogoChange(switchType);
        
    }, 150);
}

// Track logo switch for analytics
function trackLogoSwitch(switchType) {
    // Send analytics data to backend
    fetch('/api/logo/switch', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        },
        body: JSON.stringify({
            switch_type: switchType,
            timestamp: new Date().toISOString(),
            user_agent: navigator.userAgent,
            screen_resolution: `${screen.width}x${screen.height}`,
            viewport_size: `${window.innerWidth}x${window.innerHeight}`
        })
    }).catch(error => {
        console.warn('Failed to track logo switch:', error);
    });
}

// Handle logo loading errors
function handleLogoError(img) {
    console.warn('Logo failed to load:', img.src);
    
    // Try fallback image
    const fallbackSrc = '/static/image/alumni.jpeg';
    if (img.src !== fallbackSrc) {
        img.src = fallbackSrc;
        img.classList.add('fallback-logo');
        img.alt = 'Alumni Logo (Fallback)';
    } else {
        // Ultimate fallback - create a text-based logo
        createTextLogo(img);
    }
}

// Create a text-based fallback logo
function createTextLogo(img) {
    const container = img.parentElement;
    const textLogo = document.createElement('div');
    textLogo.className = 'text-logo';
    textLogo.innerHTML = '<strong>RGCACS</strong>';
    textLogo.style.cssText = `
        width: 60px;
        height: 60px;
        border-radius: 50%;
        background: linear-gradient(45deg, #FFD700, #FFA000);
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 10px;
        font-weight: bold;
        color: #333;
        text-align: center;
        line-height: 1;
    `;
    
    container.replaceChild(textLogo, img);
}

// Preload logo images for smooth switching
function preloadLogos() {
    const logoImages = [
        '/static/images/rgcacs-official-logo.png',
        '/static/images/rgcacs-logo.svg',
        '/static/image/alumni.jpeg',
        '/static/image/RGC.jpeg'
    ];
    
    logoImages.forEach(src => {
        const img = new Image();
        img.src = src;
    });
}

// Setup keyboard accessibility for logo switching
function setupLogoKeyboardAccess() {
    const logoLink = document.getElementById('logo-link');
    const logoSwitchBtn = document.querySelector('.logo-switch-btn');
    
    if (logoLink) {
        logoLink.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                window.location.href = logoLink.href;
            }
        });
    }
    
    if (logoSwitchBtn) {
        logoSwitchBtn.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                toggleLogo();
            }
        });
    }
}

// Setup comprehensive logo error handling
function setupLogoErrorHandling() {
    const logoImages = document.querySelectorAll('.logo-image');
    
    logoImages.forEach(img => {
        img.addEventListener('error', function() {
            handleLogoError(this);
        });
        
        img.addEventListener('load', function() {
            this.classList.add('logo-loaded');
        });
    });
}

// Announce logo changes for screen readers
function announceLogoChange(switchType) {
    const announcement = switchType === 'to_primary' 
        ? 'Switched to college logo' 
        : 'Switched to alumni logo';
    
    // Create or update ARIA live region
    let liveRegion = document.getElementById('logo-announcements');
    if (!liveRegion) {
        liveRegion = document.createElement('div');
        liveRegion.id = 'logo-announcements';
        liveRegion.setAttribute('aria-live', 'polite');
        liveRegion.setAttribute('aria-atomic', 'true');
        liveRegion.style.cssText = `
            position: absolute;
            left: -10000px;
            width: 1px;
            height: 1px;
            overflow: hidden;
        `;
        document.body.appendChild(liveRegion);
    }
    
    liveRegion.textContent = announcement;
}

// Logo management utilities for admin
function previewLogoUpload(input) {
    if (input.files && input.files[0]) {
        const reader = new FileReader();
        const preview = document.getElementById('logo-preview');
        
        reader.onload = function(e) {
            if (preview) {
                preview.src = e.target.result;
                preview.style.display = 'block';
            }
        };
        
        reader.readAsDataURL(input.files[0]);
    }
}

// Validate logo file before upload
function validateLogoFile(input) {
    const file = input.files[0];
    const maxSize = 5 * 1024 * 1024; // 5MB
    const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/svg+xml', 'image/gif'];
    
    if (!file) return true;
    
    if (file.size > maxSize) {
        alert('File size must be less than 5MB');
        input.value = '';
        return false;
    }
    
    if (!allowedTypes.includes(file.type)) {
        alert('Please select a valid image file (JPEG, PNG, SVG, GIF)');
        input.value = '';
        return false;
    }
    
    return true;
}

// Logo system health check
function checkLogoSystemHealth() {
    const requiredElements = {
        primaryLogo: document.getElementById('primary-logo'),
        secondaryLogo: document.getElementById('secondary-logo'),
        logoWrapper: document.querySelector('.logo-wrapper'),
        logoSwitchBtn: document.querySelector('.logo-switch-btn')
    };
    
    const missing = [];
    Object.keys(requiredElements).forEach(key => {
        if (!requiredElements[key]) {
            missing.push(key);
        }
    });
    
    if (missing.length > 0) {
        console.warn('Logo system missing elements:', missing);
        return false;
    }
    
    return true;
}

// Initialize logo system health monitoring
if (typeof window !== 'undefined') {
    window.addEventListener('load', function() {
        setTimeout(checkLogoSystemHealth, 1000);
    });
}



