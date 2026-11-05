创建 skill 快捷方式

```shel
leion@ROG:~$ cd ~/T/agent-secops/
leion@ROG:~/T/agent-secops$ cd .claude/skills/
leion@ROG:~/T/agent-secops/.claude/skills$ ln -sv ../../skills/secops-alert-analysis/ .
'./secops-alert-analysis' -> '../../skills/secops-alert-analysis/'
leion@ROG:~/T/agent-secops/.claude/skills$ cd ../../.opencode/skills
leion@ROG:~/T/agent-secops/.opencode/skills$ ln -sv ../../skills/secops-alert-analysis/ .
'./secops-alert-analysis' -> '../../skills/secops-alert-analysis/'
leion@ROG:~/T/agent-secops/.claude/skills$ cd ../../.codex/skills
leion@ROG:~/T/agent-secops/.codex/skills$ ln -sv ../../skills/secops-alert-analysis/ .
'./secops-alert-analysis' -> '../../skills/secops-alert-analysis/'
```

