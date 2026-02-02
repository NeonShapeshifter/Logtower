import React, { useState } from 'react';
import { Box, Text } from 'ink';
import TextInput from 'ink-text-input';

export const ReplInput = ({ onSubmit, isProcessing, visible = true }: { onSubmit: (cmd: string) => void, isProcessing: boolean, visible?: boolean }) => {
  const [query, setQuery] = useState('');

  if (!visible) return null;

  const handleSubmit = (val: string) => {
    if (isProcessing) return;
    setQuery('');
    onSubmit(val);
  };

  return (
    <Box borderStyle="single" borderColor={isProcessing ? 'yellow' : 'green'} width="100%">
      <Text color="green" bold>logtower&gt; </Text>
      <Box flexGrow={1}>
        <TextInput 
            value={query} 
            onChange={setQuery} 
            onSubmit={handleSubmit}
            placeholder={isProcessing ? "Run in progress — Ctrl+C to cancel" : "Type 'help' or 'hunt <file>'"}
            focus={!isProcessing}
        />
      </Box>
    </Box>
  );
};
