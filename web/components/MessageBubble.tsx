export function MessageBubble({ question, time }: { question: string; time: string }) {
  return (
    <div className="flex justify-end">
      <div className="flex max-w-[720px] items-center gap-4 rounded-md border border-question-border bg-question-bg px-[14px] py-[10px]">
        <p className="text-[13px] text-text-primary">{question}</p>
        <span className="shrink-0 font-mono text-[10px] text-text-muted">{time}</span>
        <span className="shrink-0 text-[10px] font-bold text-accent">AN</span>
      </div>
    </div>
  );
}

export default MessageBubble;
