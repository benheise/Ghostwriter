/// Tag editor, also used for other string lists such as CVE identifiers.

import * as Y from "yjs";
import Tagify from "@yaireo/tagify";
import { useEffect, useMemo, useRef } from "react";
import { HocuspocusProvider } from "@hocuspocus/provider";
import { FocusedUsersList, setFocusStyles, useYMapFocus } from "./focus";

export function TagEditor(props: {
    connected: boolean;
    provider: HocuspocusProvider;
    docKey: string;
    id?: string;
    className?: string;
    /// Placeholder text shown when the list is empty
    placeholder?: string;
    /// Only entries matching this pattern, after `transform`, are kept
    pattern?: RegExp;
    /// Normalizes an entry before it is checked and stored
    transform?: (value: string) => string;
    /// Regular expression source for the characters that separate entries
    delimiters?: string;
}) {
    const isValid = (value: string) =>
        !props.pattern || props.pattern.test(value);

    const map = useMemo(
        () => props.provider.document.get(props.docKey, Y.Map<boolean>),
        [props.provider, props.docKey]
    );

    const { focusedUsers, onFocus, onBlur } = useYMapFocus(
        props.provider.awareness!,
        map,
        ""
    );

    const inputRef = useRef<HTMLInputElement>(null);
    const taggify = useRef<Tagify | null>(null);
    useEffect(() => {
        taggify.current = new Tagify(inputRef.current!, {
            createInvalidTags: false,
            skipInvalid: true,
            classNames: {
                namespace: "tagify form-control",
            },
            placeholder: props.placeholder ?? "ATT&CK:T1555, privesc, ...",
            ...(props.pattern ? { pattern: props.pattern } : {}),
            ...(props.delimiters ? { delimiters: props.delimiters } : {}),
            ...(props.transform
                ? {
                      transformTag: (tagData: Tagify.TagData) => {
                          tagData.value = props.transform!(tagData.value);
                      },
                  }
                : {}),
        });

        taggify.current.addTags(Array.from(map.keys()));

        map.observe((ev, _tx) => {
            for (const key of ev.keysChanged) {
                if (map.has(key) && !taggify.current?.isTagDuplicate(key))
                    taggify.current?.addTags([key]);
                else if (!map.has(key) && taggify.current?.isTagDuplicate(key))
                    taggify.current?.removeTags([key], true);
            }
        });

        taggify.current.on("add", (ev) => {
            //console.log("add", ev.detail);
            const tag = ev.detail.data!.value;
            if (!isValid(tag)) return;
            if (!map.get(tag)) {
                // Don't re-add tags - doing so causes redundant updates and history entries.
                map.set(tag, true);
            }
        });
        taggify.current.on("remove", (ev) => {
            //console.log("remove", ev.detail);
            if (ev.detail.data !== undefined) map.delete(ev.detail.data.value);
        });
        taggify.current.on("edit:updated", (ev) => {
            //console.log("edit:updated", ev.detail);
            const oldTag = (ev.detail as any).previousData.value as string; // types broken
            const newTag = ev.detail.data!.tag.value;
            if (oldTag === newTag) return;
            map.delete(oldTag);
            if (isValid(newTag)) map.set(newTag, true);
        });
        taggify.current.on("focus", onFocus);
        taggify.current.on("blur", onBlur);

        return () => {
            taggify.current?.destroy();
        };
    }, [map]);

    const style = setFocusStyles(focusedUsers);
    useEffect(() => {
        taggify.current!.DOM.scope.style.setProperty(
            "outline",
            (style.outline ?? "") as string
        );
    }, [style.outline]);

    useEffect(() => {
        if (taggify.current) taggify.current.setDisabled(!props.connected);
    }, [props.connected]);

    return (
        <>
            <input id={props.id} type="text" ref={inputRef} />
            <FocusedUsersList focusedUsers={focusedUsers} />
        </>
    );
}
