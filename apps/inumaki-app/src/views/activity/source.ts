/** Unix seconds as the local date and time. */
export const when = (at: number) => new Date(at * 1000).toLocaleString();

/** The reserved dataset of the model-API proxy (M8): records and journal of proxied chat. */
export const CHAT_DATASET = "inumaki-chat";

/** How a data source is named in the Activity view's table text (the source chip says "Chat"). */
export function sourceLabel(id: string, name?: string): string {
  return id === CHAT_DATASET ? "Chat (model-API proxy)" : (name ?? id);
}
