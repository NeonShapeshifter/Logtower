/**
 * useAppState hook - Centralized state management for the Logtower TUI
 * Extracts state logic from App.tsx for better modularity
 */

import { useState, useCallback } from 'react';
import { AppState, AppView, IntelStatus, createInitialState } from '../types/index.js';

export type AppStateActions = {
  goBackToSplash: () => void;
  showError: (msg: string) => void;
  toggleRepl: () => void;
  cancelRun: () => void;
  setView: (view: AppView) => void;
  updateIntelStatus: (status: Partial<IntelStatus>) => void;
};

export type UseAppStateReturn = {
  state: AppState;
  setState: React.Dispatch<React.SetStateAction<AppState>>;
  actions: AppStateActions;
};

/**
 * Hook for managing application state
 * Provides state and common state manipulation actions
 */
export function useAppState(): UseAppStateReturn {
  const [state, setState] = useState<AppState>(createInitialState());

  const goBackToSplash = useCallback(() => {
    setState(prev => ({
      ...prev,
      view: 'VIEW_SPLASH'
    }));
  }, []);

  const showError = useCallback((msg: string) => {
    setState(prev => ({
      ...prev,
      view: 'VIEW_ERROR',
      errorMessage: msg
    }));
  }, []);

  const toggleRepl = useCallback(() => {
    setState(prev => ({ ...prev, replVisible: !prev.replVisible }));
  }, []);

  const cancelRun = useCallback(() => {
    setState(prev => {
      // Kill the active process if it exists
      if (prev.activeProcess) {
        prev.activeProcess.kill();
      }
      return {
        ...prev,
        isProcessing: false,
        activeProcess: undefined
      };
    });
  }, []);

  const setView = useCallback((view: AppView) => {
    setState(prev => ({ ...prev, view }));
  }, []);

  const updateIntelStatus = useCallback((status: Partial<IntelStatus>) => {
    setState(prev => ({
      ...prev,
      intelStatus: { ...prev.intelStatus, ...status }
    }));
  }, []);

  const actions: AppStateActions = {
    goBackToSplash,
    showError,
    toggleRepl,
    cancelRun,
    setView,
    updateIntelStatus,
  };

  return { state, setState, actions };
}
