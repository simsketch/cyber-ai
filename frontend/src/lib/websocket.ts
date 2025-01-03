import { useEffect, useRef, useState } from 'react'
import { useUser } from '@clerk/nextjs'

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

type WebSocketMessage = {
  type: 'scan_update'
  scan_id: string
  status: 'pending' | 'in-progress' | 'completed' | 'failed'
  progress?: number
  message?: string
  error?: string
}

export function useWebSocket() {
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null)
  const [isConnected, setIsConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const { user } = useUser()
  const reconnectTimeoutRef = useRef<NodeJS.Timeout>()

  useEffect(() => {
    if (!user?.id) return

    function connect() {
      try {
        // Parse the API URL to get the host
        const apiUrl = new URL(API_BASE_URL)
        // Create WebSocket URL using the same host but with ws/wss protocol
        const protocol = apiUrl.protocol === 'https:' ? 'wss:' : 'ws:'
        const wsUrl = `${protocol}//${apiUrl.host}/ws/${user.id}`
        console.log('Connecting to WebSocket:', wsUrl)
        
        if (wsRef.current?.readyState === WebSocket.OPEN) {
          console.log('WebSocket already connected')
          return
        }
        
        const ws = new WebSocket(wsUrl)
        wsRef.current = ws

        // Connection opened
        ws.addEventListener('open', () => {
          console.log('WebSocket Connected')
          setIsConnected(true)
        })

        // Listen for messages
        ws.addEventListener('message', (event) => {
          try {
            const message = JSON.parse(event.data)
            console.log('WebSocket message received:', message)
            setLastMessage(message)
          } catch (error) {
            console.error('Error parsing WebSocket message:', error)
          }
        })

        // Connection closed
        ws.addEventListener('close', (event) => {
          console.log('WebSocket Disconnected:', event.code, event.reason)
          setIsConnected(false)
          wsRef.current = null
          
          // Don't reconnect if it was a normal closure
          if (event.code !== 1000) {
            // Try to reconnect after 5 seconds
            reconnectTimeoutRef.current = setTimeout(() => {
              console.log('Attempting to reconnect...')
              connect()
            }, 5000)
          }
        })

        // Connection error
        ws.addEventListener('error', (error) => {
          console.error('WebSocket Error:', error)
          setIsConnected(false)
        })
      } catch (error) {
        console.error('Error creating WebSocket connection:', error)
        setIsConnected(false)
      }
    }

    connect()

    // Cleanup on unmount
    return () => {
      if (wsRef.current) {
        wsRef.current.close(1000, 'Component unmounting')
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
      }
    }
  }, [user?.id]) // Reconnect if user ID changes

  return { lastMessage, isConnected }
} 