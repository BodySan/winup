// Based on org.cryptomator: jfuse-win 0.7.3 (LGPL-3.0-or-later).
// WinUp lifecycle fix; the original source is in vendor/upstream/jfuse-0.7.3.zip.
package org.cryptomator.jfuse.win;

import org.cryptomator.jfuse.api.FuseMount;
import org.cryptomator.jfuse.win.extr.fuse3.fuse_h;
import java.lang.foreign.MemorySegment;

record FuseMountImpl(MemorySegment fuse, FuseArgs fuseArgs) implements FuseMount {
    @Override
    public int loop() {
        // Preserve upstream's workaround for jfuse issue #31.
        return fuseArgs.multiThreaded() ? fuse_h.fuse3_loop_mt_31(fuse, 0) : fuse_h.fuse3_loop(fuse);
    }

    @Override
    public void unmount() {
        // WinFsp 2.1 fuse3_unmount frees f3->fuse, unlike a POSIX unmount.
        // Signal the loop first. Fuse.close waits for its executor to exit
        // before calling destroy; freeing here races the native loop.
        fuse_h.fuse3_exit(fuse);
    }

    @Override
    public void destroy() {
        fuse_h.fuse3_unmount(fuse);
        fuse_h.fuse3_destroy(fuse);
    }
}
