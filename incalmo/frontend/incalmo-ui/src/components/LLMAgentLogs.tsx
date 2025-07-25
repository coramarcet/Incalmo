import React, { useRef, useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Chip,
  Divider,
  Alert,
  CircularProgress,
  IconButton
} from '@mui/material';
import { LLMAgentLogsProps, LLMAgentLogEntry } from '../types';
import { Terminal, Code, Close } from '@mui/icons-material';

const LLMAgentLogs = ({ logs, isConnected, error, onClose, hostIp }: LLMAgentLogsProps) => {
  const logContainerRef = useRef<HTMLDivElement>(null);
  const [processedLogs, setProcessedLogs] = useState<LLMAgentLogEntry[]>([]);

  useEffect(() => {
    // Combine all logs into a single string
    const combinedLogs = logs.join('\n');
    console.log("Combined logs:", combinedLogs);
    
    const extractedLogs: LLMAgentLogEntry[] = [];
    
    // Find tags in order of appearance
    const tagRegex = /<(bash|response)>([\s\S]*?)<\/\1>/g;
    let match;
    
    while ((match = tagRegex.exec(combinedLogs)) !== null) {
      const tagType = match[1] as 'bash' | 'response';
      const content = match[2].trim();
      
      extractedLogs.push({
        type: tagType,
        content: content
      });
    }
    
    console.log("Final processed logs:", extractedLogs);
    setProcessedLogs(extractedLogs);
  }, [logs]);
  
  // Auto-scroll to bottom whenever content changes
  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [processedLogs]);

  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <Box sx={{
        p: 1.5,
        backgroundColor: 'primary.dark',
        color: 'primary.contrastText',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center'
      }}>
        <Typography variant="h6">LLM Agent Activity</Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Chip
            label={isConnected ? 'Connected' : 'Disconnected'}
            color={isConnected ? 'success' : 'error'}
            size="small"
          />
          {onClose && (
            <IconButton 
              size="small" 
              color="inherit" 
              onClick={onClose}
              sx={{ ml: 1 }}
            >
              <Close />
            </IconButton>
          )}
        </Box>
      </Box>

      <Divider />

      {error && (
        <Alert severity="error" sx={{ m: 1 }}>{error}</Alert>
      )}

      <Box
        sx={{
          flex: 1,
          overflow: 'hidden',
          p: 0.5,
          backgroundColor: 'background.default',
        }}
      >
        {processedLogs.length === 0 && !error ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
            <CircularProgress size={20} sx={{ mr: 1 }} />
            <Typography color="text.secondary">Waiting for agent activity...</Typography>
          </Box>
        ) : (
          <Box
            ref={logContainerRef}
            sx={{
              backgroundColor: 'background.paper',
              borderRadius: 1,
              borderLeft: 4,
              borderColor: 'primary.main',
              p: 1.5,
              height: '100%',
              overflow: 'auto',
              '&::-webkit-scrollbar': {
                width: '8px',
                height: '8px',
              },
              '&::-webkit-scrollbar-track': {
                backgroundColor: 'transparent',
              },
              '&::-webkit-scrollbar-thumb': {
                backgroundColor: 'rgba(0, 0, 0, 0.2)',
                borderRadius: '4px',
                '&:hover': {
                  backgroundColor: 'rgba(0, 0, 0, 0.3)',
                },
              },
            }}
          >
            {processedLogs.map((log, index) => (
              <Box key={index} sx={{ mb: 2 }}>
                <Box 
                  sx={{ 
                    display: 'flex', 
                    alignItems: 'center',
                    mb: 0.5,
                    color: log.type === 'bash' ? 'success.main' : 'info.main'
                  }}
                >
                  {log.type === 'bash' ? (
                    <>
                      <Terminal fontSize="small" sx={{ mr: 1 }} />
                      <Typography variant="caption" fontWeight="bold">COMMAND</Typography>
                    </>
                  ) : (
                    <>
                      <Code fontSize="small" sx={{ mr: 1 }} />
                      <Typography variant="caption" fontWeight="bold">OUTPUT</Typography>
                    </>
                  )}
                </Box>
                
                <Box 
                  sx={{ 
                    backgroundColor: log.type === 'bash' ? '#0a3d0a' : '#162b40',
                    borderRadius: 1,
                    p: 1,
                    pl: 2,
                    fontFamily: 'monospace',
                    fontSize: '0.8rem',
                    overflow: 'auto',
                    maxHeight: log.type === 'response' ? '300px' : 'auto',
                    color: log.type === 'bash' ? '#4caf50' : '#64b5f6'
                  }}
                >
                  <pre style={{ 
                    margin: 0,
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word'
                  }}>
                    {log.content}
                  </pre>
                </Box>
              </Box>
            ))}
          </Box>
        )}
      </Box>
    </Box>
  );
};

export default LLMAgentLogs;