import { Email } from "../Email";
import { Folders } from "../Folders";
import { McpServers } from "../McpServers";

export function StepData() {
  return (
    <>
      <Email embedded />
      <Folders embedded />
      <McpServers embedded />
    </>
  );
}
