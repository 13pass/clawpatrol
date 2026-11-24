-- 0035_drop_device_os_hostname — undo 0033. An agent-prompt join now
-- names its device <machine>-<account> itself (--hostname), so the
-- gateway no longer records the OS hostname the client reported nor
-- lists a joining device's neighbours on the same machine.

ALTER TABLE devices DROP COLUMN os_hostname;
