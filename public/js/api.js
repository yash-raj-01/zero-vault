class ApiClient {
  constructor(baseUrl = '/api') {
    this.baseUrl = baseUrl;
  }

  async request(endpoint, options = {}) {
    try {
      const response = await fetch(`${this.baseUrl}${endpoint}`, {
        headers: { 'Content-Type': 'application/json' },
        ...options
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'API Request Failed');
      }
      return data;
    } catch (err) {
      console.error('API Error:', err);
      throw err;
    }
  }

  async get(endpoint) {
    return this.request(endpoint, { method: 'GET' });
  }

  async post(endpoint, body) {
    return this.request(endpoint, {
      method: 'POST',
      body: JSON.stringify(body)
    });
  }
}

window.api = new ApiClient();
