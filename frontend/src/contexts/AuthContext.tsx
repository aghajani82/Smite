import { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import api from '../api/client'

interface AuthContextType {
  isAuthenticated: boolean
  username: string | null
  login: (token: string, username: string) => void
  logout: () => Promise<boolean>
  checkAuth: () => Promise<boolean>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export const useAuth = () => {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

interface AuthProviderProps {
  children: ReactNode
}

export const AuthProvider = ({ children }: AuthProviderProps) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [username, setUsername] = useState<string | null>(null)

  const clearLocalSession = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('username')
    delete api.defaults.headers.common['Authorization']
    setIsAuthenticated(false)
    setUsername(null)
  }

  useEffect(() => {
    const token = localStorage.getItem('token')
    const savedUsername = localStorage.getItem('username')
    
    if (token && savedUsername) {
      // Verify token is still valid
      checkAuth().catch(() => {
        clearLocalSession()
      })
    }
  }, [])

  const checkAuth = async (): Promise<boolean> => {
    try {
      const token = localStorage.getItem('token')
      if (!token) {
        setIsAuthenticated(false)
        setUsername(null)
        return false
      }

      // Set token in axios default headers
      api.defaults.headers.common['Authorization'] = `Bearer ${token}`
      
      // Verify token by calling /me endpoint
      const response = await api.get('/auth/me')
      
      setIsAuthenticated(true)
      setUsername(response.data.username || localStorage.getItem('username'))
      return true
    } catch (error) {
      // A failed /me check is not a user-initiated global sign-out.
      clearLocalSession()
      return false
    }
  }

  const login = (token: string, username: string) => {
    localStorage.setItem('token', token)
    localStorage.setItem('username', username)
    api.defaults.headers.common['Authorization'] = `Bearer ${token}`
    setIsAuthenticated(true)
    setUsername(username)
  }

  const logout = async (): Promise<boolean> => {
    if (!localStorage.getItem('token')) {
      clearLocalSession()
      return true
    }
    try {
      // Wait for server acknowledgment BEFORE deleting the only bearer
      // that lets us retry revocation after a transient network failure.
      await api.post('/auth/logout', {}, { timeout: 7000 })
    } catch (error: any) {
      if (error?.response?.status !== 401) {
        // Keep the account available for one-click retry; do not pretend
        // that a network timeout revoked a valid seven-day JWT.
        return false
      }
      // Already revoked or expired is equivalent to a successful logout.
    }
    clearLocalSession()
    return true
  }

  return (
    <AuthContext.Provider
      value={{
        isAuthenticated,
        username,
        login,
        logout,
        checkAuth,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

