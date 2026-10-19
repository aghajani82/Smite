import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
})

const token = localStorage.getItem('token')
if (token) {
  api.defaults.headers.common['Authorization'] = `Bearer ${token}`
}

api.interceptors.response.use(
  (response) => response,
  (error) => {
    // An invalid *password or MFA code* is a form-level error, not
    // evidence that the current session's bearer token has expired.
    // In particular, do not kick an already signed-in operator out of
    // Settings when they mistype the 2FA setup or disable confirmation.
    const url = String(error.config?.url || '').split('?')[0]
    const factorInputError = [
      '/auth/login',
      '/auth/2fa/setup',
      '/auth/2fa/enable',
      '/auth/2fa/disable',
    ].some(path => url === path || url === '/api' + path)
    if (error.response?.status === 401 && !factorInputError) {
      localStorage.removeItem('token')
      localStorage.removeItem('username')
      delete api.defaults.headers.common['Authorization']
      
      if (window.location.pathname !== '/login') {
        window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  }
)

export default api

