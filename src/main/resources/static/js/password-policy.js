document.addEventListener('DOMContentLoaded', () => {
  const policyRules = {
    length: password => password.length >= 8,
    uppercase: password => /[A-Z]/.test(password),
    lowercase: password => /[a-z]/.test(password),
    digit: password => /\d/.test(password),
    special: password => /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password),
    whitespace: password => !/\s/.test(password),
  };

  const passwordForms = document.querySelectorAll('form[data-password-policy]');

  passwordForms.forEach(form => {
    const passwordInput = form.querySelector('input[name=password]');
    const confirmInput = form.querySelector('input[name=confirmPassword]');
    const submitButton = form.querySelector('[type=submit]');
    const policyItems = Array.from(form.querySelectorAll('[data-policy-rule]'));
    const confirmMessage = form.querySelector('.policy-confirm-message');

    if (!passwordInput || !confirmInput || !submitButton || !policyItems.length) {
      return;
    }

    const updatePolicyState = () => {
      const password = passwordInput.value;
      const confirmPassword = confirmInput.value;
      let valid = true;

      policyItems.forEach(item => {
        const ruleName = item.dataset.policyRule;
        const ruleFn = policyRules[ruleName];
        if (!ruleFn) return;

        if (ruleFn(password)) {
          item.classList.add('valid');
          item.classList.remove('invalid');
        } else {
          item.classList.add('invalid');
          item.classList.remove('valid');
          valid = false;
        }
      });

      if (confirmPassword.length > 0) {
        if (password !== confirmPassword) {
          confirmMessage.textContent = 'Passwords do not match.';
          confirmInput.classList.add('input-invalid');
          valid = false;
        } else {
          confirmMessage.textContent = '';
          confirmInput.classList.remove('input-invalid');
        }
      } else {
        confirmMessage.textContent = '';
        confirmInput.classList.remove('input-invalid');
      }

      if (password.length === 0) {
        passwordInput.classList.add('input-invalid');
      } else {
        passwordInput.classList.remove('input-invalid');
      }

      submitButton.disabled = !valid;
    };

    passwordInput.addEventListener('input', updatePolicyState);
    confirmInput.addEventListener('input', updatePolicyState);

    updatePolicyState();
  });
});
