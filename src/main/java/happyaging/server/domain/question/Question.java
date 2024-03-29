package happyaging.server.domain.question;

import happyaging.server.domain.option.Option;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Getter
@Table(uniqueConstraints = {@UniqueConstraint(name = "UNIQUE_NUMBER", columnNames = "number")})
public class Question {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "question_id")
    private Long id;

    @Column(nullable = false)
    private String number;

    @Column(nullable = false)
    private String content;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private QuestionType questionType;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private ResponseType responseType;

    private String image;

    @Column(nullable = false)
    private Boolean valid;

    @OneToMany(mappedBy = "question")
    private List<Option> options = new ArrayList<>();

    public static Question create(String number, String content, QuestionType questionType, ResponseType responseType) {
        return Question.builder()
                .number(number)
                .content(content)
                .questionType(questionType)
                .responseType(responseType)
                .options(new ArrayList<>())
                .valid(Boolean.TRUE)
                .build();
    }

    public void delete() {
        this.number = UUID.randomUUID().toString();
        this.valid = false;
    }
}
