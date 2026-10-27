"use client";

import { useCallback, useState } from "react";
import { MessagesSquare, Plus } from "lucide-react";
import { useHealth } from "@/hooks/useHealth";
import { ApiError, askQuestion, type Pipeline } from "@/lib/api";
import { PipelinePanel } from "@/components/PipelinePanel";
import { MessageBubble } from "@/components/MessageBubble";
import { AnswerCard, type Turn } from "@/components/AnswerCard";
import { Composer } from "@/components/Composer";

const SUGGESTIONS: Record<Pipeline, string> = {
  text2cypher: "Máy nào chạy dịch vụ có lỗ hổng nằm trong KEV?",
  graphrag: "Lỗ hổng SMB nguy hiểm nhất trên domain controller là gì?",
};

let turnSeq = 0;

function nowLabel(): string {
  return new Date().toLocaleTimeString("vi-VN", { hour: "2-digit", minute: "2-digit" });
}

export default function QAPage() {
  const { health, loading: healthLoading } = useHealth();
  const [pipeline, setPipeline] = useState<Pipeline>("text2cypher");
  const [turns, setTurns] = useState<Turn[]>([]);
  const [question, setQuestion] = useState(SUGGESTIONS.text2cypher);
  const [busy, setBusy] = useState(false);

  const handlePipelineChange = useCallback((next: Pipeline) => {
    setPipeline(next);
    setQuestion((prev) =>
      Object.values(SUGGESTIONS).includes(prev) ? SUGGESTIONS[next] : prev,
    );
  }, []);

  const send = useCallback(
    async (text: string, forPipeline: Pipeline) => {
      const q = text.trim();
      if (!q || busy) return;
      const id = `turn-${++turnSeq}`;
      setTurns((prev) => [
        ...prev,
        { id, question: q, pipeline: forPipeline, askedAt: nowLabel(), status: "pending" },
      ]);
      setBusy(true);
      setQuestion("");
      try {
        const answer = await askQuestion(forPipeline, q);
        setTurns((prev) =>
          prev.map((t) => (t.id === id ? { ...t, status: "done", answer } : t)),
        );
      } catch (e) {
        const message =
          e instanceof ApiError ? e.message : e instanceof Error ? e.message : String(e);
        setTurns((prev) =>
          prev.map((t) => (t.id === id ? { ...t, status: "error", errorMessage: message } : t)),
        );
      } finally {
        setBusy(false);
      }
    },
    [busy],
  );

  const handleNewSession = useCallback(() => {
    setTurns([]);
    setQuestion(SUGGESTIONS[pipeline]);
  }, [pipeline]);

  return (
    <div className="flex flex-col gap-5 p-6">
      <div className="flex items-center justify-between">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-[10px]">
            <h1 className="text-[25px] font-semibold text-text-primary">Hỏi-đáp bảo mật</h1>
            <span className="rounded bg-chip px-[7px] py-[2px] text-[11px] font-semibold text-text-secondary">
              AI ANALYST
            </span>
          </div>
          <p className="text-[12px] text-text-secondary">
            Từ câu hỏi tự nhiên đến bằng chứng đồ thị. Mọi kết luận đều có nguồn kiểm chứng.
          </p>
        </div>
      </div>

      <div className="flex flex-col items-start gap-4 lg:flex-row">
        <PipelinePanel
          pipeline={pipeline}
          onChange={handlePipelineChange}
          health={health}
          healthLoading={healthLoading}
        />

        <div className="flex min-w-0 flex-1 flex-col gap-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-[10px]">
              <MessagesSquare className="size-4 text-text-secondary" />
              <span className="text-[12px] font-semibold text-text-primary">
                Phiên hỏi-đáp hiện tại
              </span>
              <span className="text-[11px] text-text-muted">{turns.length} lượt hỏi</span>
            </div>
            <button
              type="button"
              onClick={handleNewSession}
              className="flex items-center gap-2 rounded-md border border-border bg-chip px-[10px] py-[6px] text-[12px] font-medium text-text-primary hover:bg-card"
            >
              <Plus className="size-[14px]" /> Phiên mới
            </button>
          </div>

          {turns.length === 0 && (
            <p className="rounded-lg border border-dashed border-border px-4 py-6 text-center text-[12px] text-text-muted">
              Chưa có câu hỏi nào trong phiên này — gửi câu hỏi bên dưới để bắt đầu.
            </p>
          )}

          {turns.map((turn) => (
            <div key={turn.id} className="flex flex-col gap-3">
              <MessageBubble question={turn.question} time={turn.askedAt} />
              <AnswerCard turn={turn} />
            </div>
          ))}

          <Composer
            value={question}
            onChange={setQuestion}
            onSend={() => send(question, pipeline)}
            busy={busy}
            pipeline={pipeline}
            suggestions={SUGGESTIONS}
            onPickSuggestion={(q) => send(q, pipeline)}
          />
        </div>
      </div>
    </div>
  );
}
