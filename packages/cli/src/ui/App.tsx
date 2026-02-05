import React, { useEffect } from 'react';
import { Box, Text, useApp, useInput } from 'ink';
import BigText from 'ink-big-text';
import Gradient from 'ink-gradient';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Internal components
import { ReplInput } from './components/ReplInput.js';
import { SplitView } from './components/SplitView.js';
import { Pokedex } from './screens/Pokedex.js';
import { LateralView } from './components/LateralView.js';

// Hooks
import { useAppState } from './hooks/useAppState.js';

// Commands
import { dispatchCommand, runHunt, CommandContext } from './commands/index.js';

// Types
import { AppProps } from './types/index.js';

// Constants
import {
  APP_INFO,
  HELP_TEXT,
  COMMAND_DESCRIPTIONS,
  FIXED_WIDTHS,
  SPACING,
  DEFAULTS,
} from './constants/index.js';

// Helper for paths
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '../../../..');

export const App = ({ ruleset = DEFAULTS.RULESET, initialFile }: AppProps) => {
  const { exit } = useApp();
  const { state, setState, actions } = useAppState();
  const { goBackToSplash, showError, toggleRepl, cancelRun } = actions;

  // Create command context for dispatching
  const commandContext: CommandContext = {
    getState: () => state,
    setState,
    showError,
    goBackToSplash,
    ruleset,
    repoRoot: REPO_ROOT,
  };

  const handleCommand = (cmd: string) => {
    dispatchCommand(cmd, commandContext, exit);
  };

  // Global input handler for ESC in help/error views
  useInput((input, key) => {
    if (state.view === 'VIEW_HELP' || state.view === 'VIEW_ERROR') {
      if (key.escape) {
        goBackToSplash();
      }
    }
  });

  // Handle initialFile prop
  useEffect(() => {
    if (initialFile && fs.existsSync(initialFile)) {
      runHunt(initialFile, commandContext);
    }
  }, []);

  return (
    <Box flexDirection="column" flexGrow={1} padding={SPACING.PADDING_SMALL}>
      {/* SPLASH */}
      {state.view === 'VIEW_SPLASH' && (
        <Box flexDirection="column" alignItems="flex-start" paddingLeft={4} paddingTop={2} flexGrow={1}>
          <Gradient name="morning">
            <BigText text={APP_INFO.NAME} font="block" />
          </Gradient>
          <Box marginTop={SPACING.MARGIN_SMALL}>
            <Text color="cyan" bold>{APP_INFO.TAGLINE}</Text>
          </Box>
          <Box marginTop={SPACING.MARGIN_SMALL}>
            <Text dimColor>{APP_INFO.VERSION_LABEL}</Text>
          </Box>

          <Box marginTop={SPACING.MARGIN_MEDIUM} borderStyle="round" borderColor="cyan" padding={SPACING.PADDING_SMALL} width={FIXED_WIDTHS.SPLASH_COMMAND_BOX} flexDirection="column">
            <Text bold underline>{HELP_TEXT.AVAILABLE_COMMANDS}</Text>
            <Box marginTop={SPACING.MARGIN_SMALL} flexDirection="column">
              <Text><Text color="green">  hunt {'<file>'}    </Text><Text dimColor>{COMMAND_DESCRIPTIONS.HUNT}</Text></Text>
              <Text><Text color="green">  track [file]   </Text><Text dimColor>{COMMAND_DESCRIPTIONS.TRACK}</Text></Text>
              <Text><Text color="green">  info [query]   </Text><Text dimColor>{COMMAND_DESCRIPTIONS.INFO}</Text></Text>
              <Text><Text color="green">  help (h, ?)    </Text><Text dimColor>{COMMAND_DESCRIPTIONS.HELP}</Text></Text>
              <Text><Text color="green">  exit (q)       </Text><Text dimColor>{COMMAND_DESCRIPTIONS.EXIT}</Text></Text>
            </Box>
          </Box>

          <Box marginTop={SPACING.MARGIN_SMALL} borderStyle="single" borderColor="grey" padding={SPACING.PADDING_SMALL} width={FIXED_WIDTHS.SPLASH_TIP_BOX} flexDirection="column">
            <Text bold>{HELP_TEXT.TIP_TITLE}</Text>
            <Text dimColor>{HELP_TEXT.TIP_TAB}</Text>
            <Text dimColor>{HELP_TEXT.TIP_ESC}</Text>
          </Box>
        </Box>
      )}

      {/* HELP VIEW */}
      {state.view === 'VIEW_HELP' && (
        <Box flexDirection="column" padding={SPACING.PADDING_SMALL} flexGrow={1}>
          <Box borderStyle="round" borderColor="cyan" padding={SPACING.PADDING_SMALL} flexDirection="column" width={100}>
            <Text bold color="cyan">{HELP_TEXT.COMMANDS_TITLE}</Text>
            
            {/* CORE COMMANDS */}
            <Box marginTop={SPACING.MARGIN_SMALL} flexDirection="column">
              <Text bold underline>{HELP_TEXT.ANALYSIS_SECTION}</Text>
              
              <Box flexDirection="row" marginTop={1}>
                <Box width={25}><Text color="green">  hunt {'<file>'}</Text></Box>
                <Box><Text dimColor>{COMMAND_DESCRIPTIONS.HUNT_FULL}</Text></Box>
              </Box>

              <Box flexDirection="row">
                <Box width={25}><Text color="green">  track [file]</Text></Box>
                <Box><Text dimColor>{COMMAND_DESCRIPTIONS.TRACK_FULL}</Text></Box>
              </Box>

              <Box flexDirection="row">
                <Box width={25}><Text color="green">  info [query]</Text></Box>
                <Box><Text dimColor>{COMMAND_DESCRIPTIONS.INFO_FULL}</Text></Box>
              </Box>
            </Box>

            {/* EXAMPLES SECTION */}
            <Box marginTop={SPACING.MARGIN_SMALL} flexDirection="column">
              <Text bold underline>Usage Examples:</Text>
              
              <Box marginTop={1}>
                <Text dimColor>  # Analyze with specific ruleset</Text>
              </Box>
              <Text color="yellow">  hunt Security.evtx --ruleset lateral</Text>
              
              <Box marginTop={1}>
                <Text dimColor>  # Hunt on last 24h of logs</Text>
              </Box>
              <Text color="yellow">  hunt System.evtx --hours 24</Text>

              <Box marginTop={1}>
                <Text dimColor>  # Search for 'mimikatz' rules</Text>
              </Box>
              <Text color="yellow">  info mimikatz</Text>
            </Box>

            {/* FLAGS SECTION */}
            <Box marginTop={SPACING.MARGIN_SMALL} flexDirection="column">
              <Text bold underline>Common Flags:</Text>
              <Text>  --ruleset {'<name>'}   <Text dimColor>lolbas, lateral, cred, persistence, all</Text></Text>
              <Text>  --hours {'<n>'}        <Text dimColor>Analyze only last N hours</Text></Text>
              <Text>  --limit {'<n>'}        <Text dimColor>Stop after N events</Text></Text>
            </Box>

            <Box marginTop={SPACING.MARGIN_SMALL} flexDirection="column">
              <Text bold underline>{HELP_TEXT.CONTROLS_SECTION}</Text>
              <Text dimColor>  {HELP_TEXT.SHORTCUTS.ESC_BACK}</Text>
              <Text dimColor>  {HELP_TEXT.SHORTCUTS.TAB_TOGGLE}</Text>
              <Text dimColor>  {HELP_TEXT.SHORTCUTS.CTRL_C}</Text>
            </Box>
          </Box>
          <Box marginTop={SPACING.MARGIN_SMALL}>
            <Text dimColor>{HELP_TEXT.RETURN_HINT}</Text>
          </Box>
        </Box>
      )}

      {/* ERROR VIEW */}
      {state.view === 'VIEW_ERROR' && (
        <Box flexDirection="column" flexGrow={1} borderColor="red" borderStyle="double" padding={SPACING.PADDING_SMALL}>
          <Text color="red" bold>ERROR:</Text>
          <Text>{state.errorMessage}</Text>
          <Box marginTop={SPACING.MARGIN_SMALL}>
            <Text dimColor>{HELP_TEXT.RETURN_TO_MENU}</Text>
          </Box>
        </Box>
      )}

      {/* HUNT VIEW */}
      {state.view === 'VIEW_HUNT' && (
        <SplitView
          logs={state.logs}
          findings={state.findings}
          processedCount={state.processedCount}
          isProcessing={state.isProcessing}
          activeEngines={state.activeEngines}
          ruleset={ruleset}
          onBack={goBackToSplash}
          onCancel={cancelRun}
          replVisible={state.replVisible}
          onToggleRepl={toggleRepl}
          intelStatus={state.intelStatus}
        />
      )}

      {/* TRACK VIEW */}
      {state.view === 'VIEW_TRACK' && state.trackGraph && (
        <LateralView graph={state.trackGraph} onBack={goBackToSplash} />
      )}

      {/* INFO VIEW */}
      {state.view === 'VIEW_INFO' && state.infoMatches && (
        <Pokedex matches={state.infoMatches} onBack={goBackToSplash} />
      )}

      {/* REPL - Show at bottom except when in embedded views */}
      {state.view !== 'VIEW_TRACK' && state.view !== 'VIEW_INFO' && (
        <Box marginTop={SPACING.MARGIN_SMALL}>
          <ReplInput
            onSubmit={handleCommand}
            isProcessing={state.isProcessing}
            visible={state.view === 'VIEW_HUNT' ? state.replVisible : true}
          />
        </Box>
      )}
    </Box>
  );
};
