import { ServiceSection } from "../settings/ServiceSection";

export function StepService({ onDone }: { onDone?: () => void }) {
  return <ServiceSection onDone={onDone} />;
}
