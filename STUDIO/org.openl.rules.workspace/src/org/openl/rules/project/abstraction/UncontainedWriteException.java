package org.openl.rules.project.abstraction;

import java.io.Serial;

// V1: the refusal of a project copy that a link in the destination project folder would lead out of that folder
/**
 * Signals that a project copy, such as a save, an open or a deployment, would write a file through a link that
 * leads out of the destination project folder, so nothing of the copy is written.
 *
 * <p>It is unchecked because the check may run inside the changes a repository takes one by one, after the
 * repository has prepared the folder it writes to. The message names the project folder and the file by their
 * repository paths, never by a location on disk.
 */
public final class UncontainedWriteException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    private final String refusal;

    /**
     * @param message what was refused, naming the project folder and the file by their repository paths
     */
    public UncontainedWriteException(String message) {
        super(message);
        this.refusal = message;
    }

    /**
     * @return what was refused, never {@code null}
     */
    @Override
    public String getMessage() {
        return refusal;
    }
}
