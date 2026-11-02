import { useRef } from "react";
import { inputCls, labelCls } from "@/components/ui/feedback";

/**
 * Private key input (PEM textarea or file) + optional passphrase.
 * Secrets live only in uncontrolled DOM inputs: never in React state, query cache or storage.
 * Call `read()` at submit time and `clear()` as soon as the request succeeded.
 */
export function useKeyMaterial() {
  const keyRef = useRef<HTMLTextAreaElement>(null);
  const passRef = useRef<HTMLInputElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  return {
    keyRef,
    passRef,
    fileRef,
    read: () => ({
      private_key: keyRef.current?.value.trim() ?? "",
      passphrase: passRef.current?.value || undefined,
    }),
    clear: () => {
      if (keyRef.current) keyRef.current.value = "";
      if (passRef.current) passRef.current.value = "";
      if (fileRef.current) fileRef.current.value = "";
    },
  };
}

export function KeyMaterialFields({
  km,
  idPrefix = "key",
}: {
  km: ReturnType<typeof useKeyMaterial>;
  idPrefix?: string;
}) {
  return (
    <div className="space-y-2.5">
      <div>
        <label className={labelCls} htmlFor={`${idPrefix}-pem`}>
          Private key (PEM / OpenSSH)
        </label>
        <textarea
          id={`${idPrefix}-pem`}
          ref={km.keyRef}
          rows={5}
          spellCheck={false}
          autoComplete="off"
          placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
          className="mono w-full resize-y rounded-md border border-input bg-surface p-2 text-[11.5px] outline-none placeholder:text-muted-foreground focus:border-ring"
        />
        <input
          ref={km.fileRef}
          type="file"
          aria-label="Load private key from file"
          className="mt-1 block w-full text-[11.5px] text-muted-foreground file:mr-2 file:rounded-sm file:border file:border-border file:bg-surface file:px-2 file:py-0.5 file:text-[11.5px] file:text-foreground"
          onChange={async (e) => {
            const f = e.target.files?.[0];
            if (f && km.keyRef.current) km.keyRef.current.value = (await f.text()).trim();
          }}
        />
      </div>
      <div>
        <label className={labelCls} htmlFor={`${idPrefix}-pass`}>
          Passphrase (optional)
        </label>
        <input
          id={`${idPrefix}-pass`}
          ref={km.passRef}
          type="password"
          autoComplete="new-password"
          className={inputCls}
        />
      </div>
      <p className="text-[11px] text-muted-foreground">
        The key is sent once over HTTPS, stored encrypted on the server and never shown again.
      </p>
    </div>
  );
}
