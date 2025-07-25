import { useState } from 'react';
import { useIncalmoApi } from './interfaceIncalmoApi';
import { Host } from '../types';

export const useLLMAgentAction = (onLLMAgentStart?: (hostIp: string) => void) => {
  const api = useIncalmoApi();
  const [loading, setLoading] = useState<{[key: string]: boolean}>({});
  const [error, setError] = useState<string | null>(null);

  // Scan host action
  const scanHost = async (host: Host) => {
    if (!host.ip_addresses || host.ip_addresses.length === 0) {
      setError('Host has no IP address');
      return;
    }

    const targetIp = host.ip_addresses[0];

    if (onLLMAgentStart) onLLMAgentStart(targetIp);

    setLoading(prev => ({ ...prev, [targetIp]: true }));
    setError(null);

   try {
      await api.sendLLMAgentAction('scan', {
        scan_host: targetIp,
        subnet_to_scan: targetIp
      });
      
      console.log(`Scan initiated for ${targetIp}`);
    } catch (err: any) {
      setError(err.message || 'Failed to initiate scan');
      console.error('Scan error:', err);
    } finally {
      setLoading(prev => ({ ...prev, [targetIp]: false }));
    }
  };

  return {
    scanHost,
    loading,
    error,
  };
};