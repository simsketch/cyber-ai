'use client'

import React, { createContext, useContext, useEffect, useState } from 'react'
import { useUser } from '@clerk/nextjs'

type WebSocketContextType = {
  lastMessage: any
  isConnected: boolean
}

const WebSocketContext = createContext<WebSocketContextType>({
  lastMessage: null,
  isConnected: false,
})

export function WebSocketProvider({ children }: { children: React.ReactNode }) {
  const [socket, setSocket] = useState<WebSocket | null>(null)
  const [lastMessage, setLastMessage] = useState<any>(null)
  const [isConnected, setIsConnected] = useState(false)
  const { user } = useUser()

  useEffect(() => {
    if (!user?.id) return

    // Create WebSocket connection
    const ws = new WebSocket(`ws://localhost:8000/ws/${user.id}`)

    ws.onopen = () => {
      console.log('WebSocket Connected')
      setIsConnected(true)
    }

    ws.onmessage = (event) => {
      const message = JSON.parse(event.data)
      console.log('WebSocket Message:', message)
      setLastMessage(message)
    }

    ws.onclose = () => {
      console.log('WebSocket Disconnected')
      setIsConnected(false)
      // Try to reconnect after 5 seconds
      setTimeout(() => {
        if (user?.id) {
          const newWs = new WebSocket(`ws://localhost:8000/ws/${user.id}`)
          setSocket(newWs)
        }
      }, 5000)
    }

    ws.onerror = (error) => {
      console.error('WebSocket Error:', error)
    }

    setSocket(ws)

    // Cleanup on unmount
    return () => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.close()
      }
    }
  }, [user?.id])

  return (
    <WebSocketContext.Provider value={{ lastMessage, isConnected }}>
      {children}
    </WebSocketContext.Provider>
  )
}

export const useWebSocket = () => useContext(WebSocketContext) 