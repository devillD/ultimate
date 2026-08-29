/**
 * Reusable Address Bar component shared between the Landing Page and the Browser UI Toolbar.
 * Parses, validates, and routes user input to either a direct proxied URL or a DuckDuckGo search query.
 */
export class AddressBar {
    /**
     * @param {Object} options
     * @param {HTMLFormElement} options.formElement - The form wrapper.
     * @param {HTMLInputElement} options.inputElement - The text input element.
     * @param {Function} options.onNavigate - Callback invoked with the normalized destination URL.
     */
    constructor({ formElement, inputElement, onNavigate }) {
        this.form = formElement;
        this.input = inputElement;
        this.onNavigate = onNavigate;

        if (this.form) {
            this.form.addEventListener('submit', (e) => this.handleSubmit(e));
        }
    }

    /**
     * Determines whether a given string is a valid URL or domain name.
     * @param {string} val - Raw text input from user.
     * @returns {boolean} True if input resembles a URL or domain.
     */
    static isUrl(val = '') {
        const trimmed = val.trim();
        if (!trimmed) return false;

        // Matches http://, https://, localhost, or domain with standard TLD / dots
        if (/^https?:\/\//i.test(trimmed)) return true;
        if (/^[a-z0-9-]+(\.[a-z0-9-]+)+/i.test(trimmed) && !trimmed.includes(' ')) return true;
        if (/^localhost(:\d+)?/i.test(trimmed)) return true;
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$/.test(trimmed)) return true;

        return false;
    }

    /**
     * Normalizes a search query or URL into a fully qualified HTTPS destination URL.
     * @param {string} rawInput - User input string.
     * @returns {string} Fully qualified URL string.
     */
    static formatDestination(rawInput = '') {
        const query = rawInput.trim();
        if (!query) return '';

        if (AddressBar.isUrl(query)) {
            if (/^https?:\/\//i.test(query)) {
                return query;
            }
            return 'https://' + query;
        }

        // Bare search query routed to DuckDuckGo search engine
        return `https://duckduckgo.com/?q=${encodeURIComponent(query)}`;
    }

    /**
     * Sets the displayed text in the address bar input.
     * @param {string} url - Real target URL.
     */
    setValue(url) {
        if (this.input) {
            this.input.value = url || '';
        }
    }

    /**
     * Gets the current value from the address bar input.
     * @returns {string}
     */
    getValue() {
        return this.input ? this.input.value.trim() : '';
    }

    /**
     * Handles the form submission event.
     * @param {Event} event
     */
    handleSubmit(event) {
        if (event) event.preventDefault();
        const raw = this.getValue();
        if (!raw) return;

        const targetUrl = AddressBar.formatDestination(raw);
        if (this.onNavigate && typeof this.onNavigate === 'function') {
            this.onNavigate(targetUrl);
        }
    }
}
