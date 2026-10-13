import type { Focus, ScanResult, Stage, StageData, StageId } from "../types";

export interface StageViewProps<K extends StageId = StageId> {
  stage: Stage<K>;
  result: ScanResult;
  focus: Focus;
  setFocus: (focus: Focus) => void;
  goTo: (stage: StageId, focus?: Focus) => void;
}

export function stageData<K extends StageId>(result: ScanResult, id: K): StageData[K] {
  return result.stages.find((s) => s.id === id)!.data as StageData[K];
}
