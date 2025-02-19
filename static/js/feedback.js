document.addEventListener('DOMContentLoaded', function() {
    const starRating = document.querySelector('.star-rating');
    const stars = starRating.querySelectorAll('input[type="radio"]');

    stars.forEach(star => {
        star.addEventListener('change', function() {
            const rating = this.value;
            for (let i = 0; i < stars.length; i++) {
                if (i < rating) {
                    stars[i].nextElementSibling.style.color = '#ffc107';
                } else {
                    stars[i].nextElementSibling.style.color = '#ddd';
                }
            }
        });
    });

    const feedbackForm = document.querySelector('.feedback-form');
    feedbackForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        // Perform client-side validation
        const requiredFields = feedbackForm.querySelectorAll('[required]');
        let isValid = true;

        requiredFields.forEach(field => {
            if (!field.value.trim()) {
                isValid = false;
                field.classList.add('error');
            } else {
                field.classList.remove('error');
            }
        });

        if (!isValid) {
            alert('Please fill in all required fields.');
            return;
        }

        // If valid, you can submit the form or use AJAX to send the data
        // For now, we'll just show an alert
        alert('Thank you for your feedback!');
        feedbackForm.reset();
    });
});