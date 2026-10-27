import { FlaskConical } from "lucide-react";

export function DemoBanner() {
  return (
    <div className="flex h-[30px] items-center justify-between bg-[#1b2229] px-6">
      <div className="flex items-center gap-2">
        <FlaskConical className="size-3 text-text-secondary" />
        <span className="text-[10px] text-text-secondary">Demo lab — dữ liệu mô phỏng</span>
      </div>
      <span className="text-[10px] text-text-muted">Chỉ đọc · không tác động hệ thống thực</span>
    </div>
  );
}

export default DemoBanner;
