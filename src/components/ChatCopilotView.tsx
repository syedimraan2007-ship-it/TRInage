import React, { useState, useEffect, useRef } from 'react';
import { api } from '../api';
import { Project, NormalizedFinding, AttackPath } from '../types';
import {
  Bot,
  User,
  Send,
  Sparkles,
  Trash2,
  Copy,
  Check,
  ShieldAlert,
  Terminal,
  Zap,
  Cpu,
  Layers,
  HelpCircle,
  Download,
  AlertTriangle,
  RotateCcw
} from 'lucide-react';

export type GeminiModelChoice = 'gemini-3.1-pro-preview' | 'gemini-3.5-flash' | 'gemini-3.1-flash-lite';
export type ChatRoleId = 'threat_analyst' | 'defensive_advisor' | 'remediation_engineer';

interface ChatMessage {
  id: string;
  role: 'user' | 'model';
  content: string;
  timestamp: string;
  modelUsed?: string;
  roleId?: ChatRoleId;
}

interface ChatCopilotViewProps {
  currentProject: Project | null;
  findings: NormalizedFinding[];
  attackPaths: AttackPath[];
  onNavigateTab?: (tab: string) => void;
}

const ROLES: {
  id: ChatRoleId;
  name: string;
  defaultModel: GeminiModelChoice;
  badge: string;
  tagline: string;
  description: string;
  icon: any;
}[] = [
  {
    id: 'threat_analyst',
    name: 'Threat Path Analyst',
    defaultModel: 'gemini-3.1-pro-preview',
    badge: 'Complex Tasks',
    tagline: 'Deep exploit chaining & lateral movement reasoning',
    description: 'Specializes in multi-step kill chains, privilege escalation bottlenecks, and complex vulnerability chaining.',
    icon: Cpu,
  },
  {
    id: 'defensive_advisor',
    name: 'SecOps Triage Advisor',
    defaultModel: 'gemini-3.5-flash',
    badge: 'General Tasks',
    tagline: 'Defensive architecture, severity triage & business impact',
    description: 'Assists with contextual finding triage, false-positive elimination, blast radius analysis, and defensive posture.',
    icon: Bot,
  },
  {
    id: 'remediation_engineer',
    name: 'Rapid Remediation Engineer',
    defaultModel: 'gemini-3.1-flash-lite',
    badge: 'Fast Tasks',
    tagline: 'Instant code snippets, WAF rules & verification tests',
    description: 'Generates immediate, production-ready code fixes, firewall configs, and validation test commands.',
    icon: Zap,
  },
];

export const ChatCopilotView: React.FC<ChatCopilotViewProps> = ({
  currentProject,
  findings,
  attackPaths,
  onNavigateTab,
}) => {
  const [selectedRole, setSelectedRole] = useState<ChatRoleId>('defensive_advisor');
  const [selectedModel, setSelectedModel] = useState<GeminiModelChoice>('gemini-3.5-flash');
  const [includeContext, setIncludeContext] = useState<boolean>(true);
  const [inputMessage, setInputMessage] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Initialize conversation thread with role-specific greeting
  const [messages, setMessages] = useState<ChatMessage[]>(() => {
    return [
      {
        id: 'msg-welcome',
        role: 'model',
        content: `👋 Hello! I am your **Gemini Defensive Security Copilot**.\n\nI can analyze your vulnerability evidence, evaluate multi-hop attack paths, suggest structural remediation architectures, or write immediate WAF and code patches.\n\nSelect a specialist persona above or type your question below to begin.`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        modelUsed: 'gemini-3.5-flash',
        roleId: 'defensive_advisor',
      },
    ];
  });

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // When role changes, update default model to match user requirement guidelines
  const handleRoleChange = (roleId: ChatRoleId) => {
    setSelectedRole(roleId);
    const roleDef = ROLES.find(r => r.id === roleId);
    if (roleDef) {
      setSelectedModel(roleDef.defaultModel);
    }
  };

  // Auto-scroll to bottom of conversation thread
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isLoading]);

  // Build dynamic project context for the chatbot
  const getProjectContextSummary = (): string => {
    if (!currentProject || !includeContext) return '';
    const topPaths = attackPaths.slice(0, 3).map(p => `- [${p.severity}] ${p.title} (Risk: ${p.contextualScore}/100)`).join('\n');
    const topFindings = findings.slice(0, 5).map(f => `- ${f.title} (${f.severity}, Asset: ${f.asset}, CWE: ${f.cwe || 'N/A'})`).join('\n');
    return `Project Name: ${currentProject.name}
Authorized Target Scope: ${currentProject.targetScope}
Authorized By: ${currentProject.authorizedBy}
Total Findings: ${findings.length}
Critical Attack Paths (${attackPaths.length}):
${topPaths || 'No attack paths.'}
Key Vulnerabilities:
${topFindings || 'No findings recorded.'}`;
  };

  const handleSendMessage = async (customText?: string) => {
    const textToSend = (customText || inputMessage).trim();
    if (!textToSend || isLoading) return;

    const userMessage: ChatMessage = {
      id: `msg-${Date.now()}-user`,
      role: 'user',
      content: textToSend,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    const newMessages = [...messages, userMessage];
    setMessages(newMessages);
    setInputMessage('');
    setIsLoading(true);

    try {
      // Map thread to API payload format
      const payloadMessages = newMessages
        .filter(m => m.id !== 'msg-welcome')
        .map(m => ({
          role: m.role,
          content: m.content,
        }));

      // Ensure at least one message is sent
      if (payloadMessages.length === 0) {
        payloadMessages.push({ role: 'user', content: textToSend });
      }

      const res = await api.sendChatMessage(payloadMessages, {
        model: selectedModel,
        roleId: selectedRole,
        projectId: currentProject?.id,
        contextSummary: includeContext ? getProjectContextSummary() : undefined,
      });

      const modelMessage: ChatMessage = {
        id: `msg-${Date.now()}-model`,
        role: 'model',
        content: res.reply,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        modelUsed: res.modelUsed || selectedModel,
        roleId: selectedRole,
      };

      setMessages(prev => [...prev, modelMessage]);
    } catch (err: any) {
      const errorMessage: ChatMessage = {
        id: `msg-${Date.now()}-err`,
        role: 'model',
        content: `⚠️ **Notice:** ${err.message || 'Failed to complete chat query. Please try again.'}`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        modelUsed: selectedModel,
        roleId: selectedRole,
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleClearHistory = () => {
    setMessages([
      {
        id: `msg-${Date.now()}-reset`,
        role: 'model',
        content: `🔄 Conversation history cleared. How can I assist with your defensive security assessment today?`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        modelUsed: selectedModel,
        roleId: selectedRole,
      },
    ]);
  };

  const handleExportChat = () => {
    const chatExport = {
      project: currentProject?.name,
      exportedAt: new Date().toISOString(),
      role: selectedRole,
      model: selectedModel,
      conversation: messages,
    };
    const blob = new Blob([JSON.stringify(chatExport, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `gemini-security-chat-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const activeRoleDef = ROLES.find(r => r.id === selectedRole) || ROLES[1];

  const quickPrompts = [
    {
      title: 'Analyze Root Bottleneck',
      prompt: 'Based on the loaded findings and attack paths, what is the single most critical bottleneck vulnerability that breaks the maximum number of attack paths?',
      role: 'threat_analyst' as ChatRoleId,
    },
    {
      title: 'SSRF Mitigation Policy',
      prompt: 'Provide an architectural defense-in-depth policy and WAF rule to prevent SSRF from reaching cloud metadata (169.254.169.254) and internal RFC1918 subnets.',
      role: 'remediation_engineer' as ChatRoleId,
    },
    {
      title: 'Post-Remediation Verification',
      prompt: 'How should our SecOps team verify that SQL injection and SSRF are genuinely fixed in automated follow-up scans?',
      role: 'defensive_advisor' as ChatRoleId,
    },
    {
      title: 'Explain Blast Radius',
      prompt: 'Explain the potential business and data compromise blast radius if an unauthenticated attacker accesses our internal Redis session cache.',
      role: 'defensive_advisor' as ChatRoleId,
    },
  ];

  return (
    <div className="space-y-4 max-w-6xl mx-auto flex flex-col h-[calc(100vh-140px)] min-h-[640px]">
      {/* Top Controls: Role & Model Configuration */}
      <div className="cyber-card rounded-2xl p-4 border border-slate-800 shadow-md shrink-0 space-y-3">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          {/* Header & Tagline */}
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-900 to-slate-900 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-sm">
              <Sparkles className="w-5 h-5 text-cyan-300 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-base font-bold text-slate-100">Gemini Security Chatbot</h2>
                <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800 uppercase">
                  Multi-Turn Thread
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                AI-assisted defensive triage, complex attack-path analysis, and rapid remediation code generation
              </p>
            </div>
          </div>

          {/* Model & Context Controls */}
          <div className="flex flex-wrap items-center gap-2.5">
            {/* Model Selector */}
            <div className="flex items-center space-x-1.5 bg-slate-950 border border-slate-800 rounded-xl px-2.5 py-1.5 text-xs">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              <span className="text-slate-400 font-mono text-[11px]">Model:</span>
              <select
                id="gemini-model-select"
                value={selectedModel}
                onChange={(e) => setSelectedModel(e.target.value as GeminiModelChoice)}
                className="bg-transparent text-slate-200 text-xs font-mono font-bold focus:outline-none cursor-pointer"
              >
                <option value="gemini-3.1-pro-preview" className="bg-slate-900 text-slate-200">
                  gemini-3.1-pro-preview (Complex Tasks)
                </option>
                <option value="gemini-3.5-flash" className="bg-slate-900 text-slate-200">
                  gemini-3.5-flash (General Tasks)
                </option>
                <option value="gemini-3.1-flash-lite" className="bg-slate-900 text-slate-200">
                  gemini-3.1-flash-lite (Fast Tasks)
                </option>
              </select>
            </div>

            {/* Include Context Toggle */}
            <button
              onClick={() => setIncludeContext(!includeContext)}
              className={`px-3 py-1.5 rounded-xl border text-xs font-medium flex items-center space-x-1.5 transition ${
                includeContext
                  ? 'bg-cyan-950/80 text-cyan-300 border-cyan-800/80'
                  : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
              }`}
              title="Pass active findings and attack path summary into system instruction"
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Project Context: {includeContext ? 'On' : 'Off'}</span>
            </button>

            {/* Clear History */}
            <button
              onClick={handleClearHistory}
              className="p-1.5 rounded-xl text-slate-400 hover:text-slate-200 hover:bg-slate-800 border border-slate-800 transition"
              title="Clear Thread History"
            >
              <RotateCcw className="w-4 h-4" />
            </button>

            {/* Export History */}
            <button
              onClick={handleExportChat}
              className="p-1.5 rounded-xl text-slate-400 hover:text-slate-200 hover:bg-slate-800 border border-slate-800 transition"
              title="Export Conversation"
            >
              <Download className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* 3 Specialized Role Selector Tabs */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-1 border-t border-slate-800/60">
          {ROLES.map((role) => {
            const isSelected = selectedRole === role.id;
            const Icon = role.icon;
            return (
              <button
                key={role.id}
                onClick={() => handleRoleChange(role.id)}
                className={`text-left p-2.5 rounded-xl border transition flex items-start space-x-2.5 ${
                  isSelected
                    ? 'bg-cyan-950/40 border-cyan-500/80 shadow-sm shadow-cyan-950'
                    : 'bg-slate-950/60 border-slate-800/80 hover:border-slate-700 text-slate-400'
                }`}
              >
                <div className={`p-1.5 rounded-lg mt-0.5 shrink-0 ${
                  isSelected ? 'bg-cyan-900/60 text-cyan-300' : 'bg-slate-900 text-slate-500'
                }`}>
                  <Icon className="w-4 h-4" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between">
                    <span className={`text-xs font-bold truncate ${isSelected ? 'text-cyan-200' : 'text-slate-200'}`}>
                      {role.name}
                    </span>
                    <span className={`text-[9px] font-mono px-1.5 py-0.2 rounded font-bold uppercase ${
                      role.id === 'threat_analyst'
                        ? 'bg-purple-950 text-purple-300 border border-purple-800/50'
                        : role.id === 'remediation_engineer'
                        ? 'bg-emerald-950 text-emerald-300 border border-emerald-800/50'
                        : 'bg-cyan-950 text-cyan-300 border border-cyan-800/50'
                    }`}>
                      {role.badge}
                    </span>
                  </div>
                  <p className="text-[10px] text-slate-400 truncate mt-0.5">
                    {role.tagline}
                  </p>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Chat Thread (Scrollable) */}
      <div className="cyber-card rounded-2xl p-4 sm:p-6 border border-slate-800 flex-1 overflow-y-auto space-y-4 shadow-inner">
        {messages.map((message) => {
          const isUser = message.role === 'user';
          return (
            <div
              key={message.id}
              className={`flex items-start space-x-3 ${isUser ? 'flex-row-reverse space-x-reverse' : ''}`}
            >
              {/* Avatar */}
              <div
                className={`w-8 h-8 rounded-xl flex items-center justify-center shrink-0 border ${
                  isUser
                    ? 'bg-cyan-600 text-white border-cyan-400 shadow-md shadow-cyan-950'
                    : 'bg-slate-900 text-cyan-400 border-slate-800 shadow-sm'
                }`}
              >
                {isUser ? <User className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
              </div>

              {/* Message Bubble */}
              <div
                className={`max-w-[85%] sm:max-w-[78%] rounded-2xl p-4 space-y-2 text-xs leading-relaxed shadow-md ${
                  isUser
                    ? 'bg-gradient-to-br from-cyan-950/90 to-slate-900 text-slate-100 border border-cyan-700/50'
                    : 'bg-slate-900/95 text-slate-200 border border-slate-800'
                }`}
              >
                {/* Message Header */}
                <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 border-b border-slate-800/60 pb-1.5">
                  <div className="flex items-center space-x-2">
                    <span className="font-bold text-slate-300">
                      {isUser ? 'Security Operator' : activeRoleDef.name}
                    </span>
                    {!isUser && message.modelUsed && (
                      <span className="px-1.5 py-0.2 rounded bg-slate-950 text-cyan-400 border border-slate-800">
                        {message.modelUsed}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center space-x-2">
                    <span>{message.timestamp}</span>
                    <button
                      onClick={() => handleCopy(message.id, message.content)}
                      className="text-slate-500 hover:text-slate-300 transition"
                      title="Copy message"
                    >
                      {copiedId === message.id ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </div>

                {/* Message Content with Markdown & Code styling */}
                <div className="whitespace-pre-wrap font-sans text-xs space-y-1.5 selection:bg-cyan-500/30">
                  {message.content.split('\n').map((line, lIdx) => {
                    // Check for headers
                    if (line.startsWith('### ')) {
                      return <h4 key={lIdx} className="text-sm font-bold text-cyan-300 mt-2">{line.replace('### ', '')}</h4>;
                    }
                    if (line.startsWith('## ')) {
                      return <h3 key={lIdx} className="text-sm font-bold text-slate-100 mt-2">{line.replace('## ', '')}</h3>;
                    }
                    if (line.startsWith('# ')) {
                      return <h2 key={lIdx} className="text-base font-bold text-slate-100 mt-2">{line.replace('# ', '')}</h2>;
                    }
                    // Check for code blocks
                    if (line.startsWith('```')) {
                      return <div key={lIdx} className="font-mono text-[11px] text-cyan-400/90 py-0.5">{line}</div>;
                    }
                    // Normal text
                    return <p key={lIdx} className="leading-relaxed">{line}</p>;
                  })}
                </div>
              </div>
            </div>
          );
        })}

        {/* Loading Indicator */}
        {isLoading && (
          <div className="flex items-start space-x-3">
            <div className="w-8 h-8 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-center text-cyan-400 shrink-0">
              <Bot className="w-4 h-4 animate-spin" />
            </div>
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 text-xs font-mono text-cyan-400 flex items-center space-x-2.5 shadow-sm">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
              <span>Gemini ({selectedModel}) is synthesizing threat intelligence...</span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Quick Starter Prompts */}
      <div className="flex items-center space-x-2 overflow-x-auto pb-1 scrollbar-none text-xs shrink-0">
        <span className="text-[11px] font-mono text-slate-500 uppercase tracking-wider shrink-0 flex items-center space-x-1">
          <Terminal className="w-3.5 h-3.5 text-cyan-400" />
          <span>Quick Prompts:</span>
        </span>
        {quickPrompts.map((qp, qIdx) => (
          <button
            key={qIdx}
            onClick={() => {
              handleRoleChange(qp.role);
              handleSendMessage(qp.prompt);
            }}
            className="px-3 py-1 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-cyan-300 border border-slate-800 hover:border-cyan-700/60 rounded-xl whitespace-nowrap transition text-xs font-medium shrink-0"
          >
            {qp.title}
          </button>
        ))}
      </div>

      {/* Input Message Area */}
      <div className="cyber-card rounded-2xl p-3 border border-slate-800 shadow-lg shrink-0">
        <div className="flex items-end space-x-2">
          <textarea
            ref={inputRef}
            rows={2}
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={`Ask ${activeRoleDef.name} (${selectedModel})... [Press Enter to send, Shift+Enter for new line]`}
            disabled={isLoading}
            className="flex-1 bg-slate-950 text-slate-100 placeholder-slate-500 text-xs rounded-xl p-3 border border-slate-800 focus:outline-none focus:border-cyan-500 resize-none font-sans"
          />
          <button
            id="send-chat-btn"
            onClick={() => handleSendMessage()}
            disabled={!inputMessage.trim() || isLoading}
            className="p-3 bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 disabled:from-slate-800 disabled:to-slate-800 disabled:text-slate-500 text-white rounded-xl transition shadow-md shadow-cyan-950 shrink-0"
            title="Send Message (Enter)"
          >
            <Send className="w-4 h-4" />
          </button>
        </div>

        {/* Footer Guidance */}
        <div className="flex items-center justify-between text-[11px] text-slate-500 mt-2 px-1 font-mono">
          <span>
            {currentProject ? `Active Scope: ${currentProject.name}` : 'No active project selected'}
          </span>
          <span className="hidden sm:inline">
            Model: <strong className="text-slate-400">{selectedModel}</strong>
          </span>
        </div>
      </div>
    </div>
  );
};
