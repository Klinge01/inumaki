import { ModelsSection } from "../settings/ModelsSection";

export function StepModels({ onDone }: { onDone?: () => void }) {
  return <ModelsSection onDone={onDone} />;
}
