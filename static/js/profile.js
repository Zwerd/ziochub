/**
 * Profile modal and settings.
 * Depends on globals from app.js: authState, showToast, updateAuthUI
 */

// Profile Settings Modal
const profileModal = document.getElementById('profileModal');
const profileModalClose = document.getElementById('profileModalClose');
const profileForm = document.getElementById('profileForm');
const profileAvatarUploadBtn = document.getElementById('profileAvatarUploadBtn');
const profileAvatarRemoveBtn = document.getElementById('profileAvatarRemoveBtn');
const profileAvatarFile = document.getElementById('profileAvatarFile');
const profileAvatarImg = document.getElementById('profileAvatarImg');
const profileAvatarPlaceholder = document.getElementById('profileAvatarPlaceholder');
const profileMessage = document.getElementById('profileMessage');
const profileUsername = document.getElementById('profileUsername');
const profileSource = document.getElementById('profileSource');

const profileRoleDescriptionEl = document.getElementById('profileRoleDescription');
if (profileRoleDescriptionEl && typeof window.detectDir === 'function') {
    profileRoleDescriptionEl.addEventListener('input', function () { this.setAttribute('dir', window.detectDir(this.value)); });
    profileRoleDescriptionEl.addEventListener('keyup', function () { this.setAttribute('dir', window.detectDir(this.value)); });
}

async function openProfileModal() {
    if (!profileModal || !authState.authenticated) return;
    profileModal.classList.remove('hidden');
    profileMessage.classList.add('hidden');
    if (profileRoleDescriptionEl) profileRoleDescriptionEl.setAttribute('dir', window.detectDir ? window.detectDir(profileRoleDescriptionEl.value) : 'ltr');
    
    // Load profile data
    try {
        const response = await fetch('/api/profile');
        const data = await response.json();
        if (data.success) {
            document.getElementById('profileDisplayName').value = data.display_name || data.username || '';
            const roleDescEl = document.getElementById('profileRoleDescription');
            if (roleDescEl) {
                roleDescEl.value = data.role_description || '';
                if (typeof window.detectDir === 'function') roleDescEl.setAttribute('dir', window.detectDir(roleDescEl.value));
            }
            profileUsername.textContent = data.username || 'User';
            profileSource.textContent = data.source || 'local';
            const muteSoundEl = document.getElementById('profileMuteSound');
            const ambitionPopupEl = document.getElementById('profileAmbitionPopupDisabled');
            const achievementPopupEl = document.getElementById('profileAchievementPopupDisabled');
            if (muteSoundEl) muteSoundEl.checked = !!data.mute_sound;
            if (ambitionPopupEl) ambitionPopupEl.checked = !!data.ambition_popup_disabled;
            if (achievementPopupEl) achievementPopupEl.checked = !!data.achievement_popup_disabled;

            // Update avatar display
            if (data.avatar_url) {
                profileAvatarImg.src = data.avatar_url + '?t=' + Date.now();
                profileAvatarImg.classList.remove('hidden');
                profileAvatarPlaceholder.classList.add('hidden');
            } else {
                profileAvatarImg.classList.add('hidden');
                profileAvatarPlaceholder.classList.remove('hidden');
            }
        }
    } catch (error) {
        console.error('Error loading profile:', error);
        showToast('Failed to load profile', 'error');
    }
}

if (profileModalClose) {
    profileModalClose.addEventListener('click', () => {
        if (profileModal) profileModal.classList.add('hidden');
    });
}

if (profileModal) {
    profileModal.addEventListener('click', (e) => {
        if (e.target === profileModal) {
            profileModal.classList.add('hidden');
        }
    });
}

// Open profile modal when clicking on profile button
const authProfileBtn = document.getElementById('authProfile');
if (authProfileBtn) {
    authProfileBtn.addEventListener('click', (e) => {
        e.preventDefault();
        if (!authState || !authState.authenticated) {
            // On narrow screens we hide the top Login link and use the profile button as Login entrypoint.
            window.location.href = '/login';
            return;
        }
        openProfileModal();
    });
}

// Save profile form
if (profileForm) {
    profileForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        profileMessage.classList.add('hidden');
        try {
            const response = await fetch('/api/profile', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    display_name: document.getElementById('profileDisplayName').value.trim(),
                    role_description: document.getElementById('profileRoleDescription').value.trim(),
                    mute_sound: document.getElementById('profileMuteSound').checked,
                    ambition_popup_disabled: document.getElementById('profileAmbitionPopupDisabled').checked,
                    achievement_popup_disabled: document.getElementById('profileAchievementPopupDisabled').checked
                })
            });
            const data = await response.json();
            profileMessage.classList.remove('hidden');
            if (data.success) {
                profileMessage.classList.add('text-green-400');
                profileMessage.classList.remove('text-red-400');
                profileMessage.textContent = 'Profile saved.';
                
                // Update authState and UI
                if (data.display_name) {
                    authState.display_name = data.display_name;
                    updateAuthUI();
                }
                if (data.avatar_url) {
                    authState.avatar_url = data.avatar_url;
                    updateAuthUI();
                }
                document.body.setAttribute('data-mute-sound', data.mute_sound ? '1' : '0');
                document.body.setAttribute('data-ambition-popup-disabled', data.ambition_popup_disabled ? '1' : '0');
                document.body.setAttribute('data-achievement-popup-disabled', data.achievement_popup_disabled ? '1' : '0');

                showToast('Profile saved', 'success');
            } else {
                profileMessage.classList.add('text-red-400');
                profileMessage.classList.remove('text-green-400');
                profileMessage.textContent = data.message || 'Failed to save profile.';
            }
        } catch (error) {
            profileMessage.classList.remove('hidden');
            profileMessage.classList.add('text-red-400');
            profileMessage.classList.remove('text-green-400');
            profileMessage.textContent = 'Network error.';
            console.error('Error saving profile:', error);
        }
    });
}

// Upload avatar
if (profileAvatarUploadBtn) {
    profileAvatarUploadBtn.addEventListener('click', async () => {
        if (!profileAvatarFile.files || profileAvatarFile.files.length === 0) {
            showToast('Select a file first', 'error');
            return;
        }
        const formData = new FormData();
        formData.append('file', profileAvatarFile.files[0]);
        try {
            const response = await fetch('/api/profile/avatar', { method: 'POST', body: formData });
            const data = await response.json();
            if (data.success && data.avatar_url) {
                profileAvatarPlaceholder.classList.add('hidden');
                profileAvatarImg.src = data.avatar_url + '?t=' + Date.now();
                profileAvatarImg.classList.remove('hidden');
                profileAvatarFile.value = '';
                
                // Update authState and UI
                authState.avatar_url = data.avatar_url;
                updateAuthUI();
                
                showToast('Avatar uploaded', 'success');
            } else {
                showToast(data.message || 'Upload failed', 'error');
            }
        } catch (error) {
            showToast('Network error', 'error');
            console.error('Error uploading avatar:', error);
        }
    });
}

// Remove profile photo
if (profileAvatarRemoveBtn) {
    profileAvatarRemoveBtn.addEventListener('click', async () => {
        try {
            const response = await fetch('/api/profile/avatar', { method: 'DELETE' });
            const data = await response.json();
            if (data.success) {
                profileAvatarImg.classList.add('hidden');
                profileAvatarPlaceholder.classList.remove('hidden');
                profileAvatarImg.removeAttribute('src');
                profileAvatarFile.value = '';
                authState.avatar_url = null;
                updateAuthUI();
                showToast(data.message || 'Profile picture removed', 'success');
            } else {
                showToast(data.message || 'Failed to remove photo', 'error');
            }
        } catch (error) {
            showToast('Network error', 'error');
            console.error('Error removing avatar:', error);
        }
    });
}

window.openProfileModal = openProfileModal;
