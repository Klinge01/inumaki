import { Notice } from "./Notice";

export function NotAvailable({ what }: { what: string }) {
  return (
    <Notice title="Not available yet">
      {`${what} isn't in this version of the inumaki service. Update the service to use it.`}
    </Notice>
  );
}
