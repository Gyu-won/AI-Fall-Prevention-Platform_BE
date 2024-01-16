package happyaging.server.domain.admin;

import java.util.List;
import lombok.AllArgsConstructor;

@AllArgsConstructor
public class PagingResponse<T> {
    private boolean hasNext;
    private List<T> data;
}