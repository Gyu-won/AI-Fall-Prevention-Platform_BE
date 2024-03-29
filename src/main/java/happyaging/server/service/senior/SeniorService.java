package happyaging.server.service.senior;

import happyaging.server.domain.image.ExampleImage;
import happyaging.server.domain.image.Location;
import happyaging.server.domain.image.SeniorImage;
import happyaging.server.domain.senior.Senior;
import happyaging.server.domain.user.User;
import happyaging.server.dto.admin.senior.ReadSeniorImageDTO;
import happyaging.server.dto.senior.ImageResponseDTO;
import happyaging.server.dto.senior.SeniorRequestDTO;
import happyaging.server.dto.senior.SeniorResponseDTO;
import happyaging.server.exception.AppException;
import happyaging.server.exception.errorcode.AppErrorCode;
import happyaging.server.repository.image.ExampleImageRepository;
import happyaging.server.repository.image.SeniorImageRepository;
import happyaging.server.repository.senior.SeniorRepository;
import happyaging.server.repository.user.UserRepository;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

@Service
@Slf4j
@RequiredArgsConstructor
public class SeniorService {

    private final UserRepository userRepository;
    private final SeniorRepository seniorRepository;
    private final ExampleImageRepository exampleImageRepository;
    private final SeniorImageRepository seniorImageRepository;

    @Value("${file.senior-room}")
    private String uploadDir;

    @Transactional
    public Senior createSenior(Long userId, SeniorRequestDTO seniorRequestDTO) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AppException(AppErrorCode.INVALID_USER));
        Senior senior = Senior.create(user, seniorRequestDTO);
        seniorRepository.save(senior);
        return senior;
    }

    @Transactional
    public void updateSenior(Long seniorId, SeniorRequestDTO seniorRequestDTO) {
        Senior senior = findSeniorById(seniorId);
        senior.update(seniorRequestDTO);
    }

    @Transactional
    public void deleteSenior(Long seniorId) {
        Senior senior = findSeniorById(seniorId);
        senior.delete();
    }

    @Transactional(readOnly = true)
    public List<SeniorResponseDTO> readSeniors(Long userId) {
        List<Senior> seniors = findSeniorByUserId(userId);
        return seniors.stream()
                .map(SeniorResponseDTO::create)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<Senior> findSeniorByUserId(Long userId) {
        List<Senior> seniors = seniorRepository.findByUserId(userId);
        return Optional.ofNullable(seniors)
                .orElseGet(Collections::emptyList);
    }

    @Transactional(readOnly = true)
    public Senior findSeniorById(Long seniorId) {
        return seniorRepository.findById(seniorId)
                .orElseThrow(() -> new AppException(AppErrorCode.INVALID_SENIOR));
    }

    @Transactional(readOnly = true)
    public List<ImageResponseDTO> readExampleImage() {
        List<ExampleImage> exampleImages = exampleImageRepository.findAllByOrderByIdAsc();
        return exampleImages.stream()
                .map(ImageResponseDTO::create)
                .toList();
    }

    @Transactional
    public void saveSeniorImages(Long seniorId, String location, MultipartFile[] imageFiles) {
        Senior senior = findSeniorById(seniorId);
        for (MultipartFile file : imageFiles) {
            if (!file.isEmpty()) {
                String filePath = saveFile(file);
                saveFileData(senior, filePath, location);
            }
        }
    }

    private String saveFile(MultipartFile file) {
        try {
            String originalFilename = file.getOriginalFilename();
            String fileExtension = originalFilename.substring(originalFilename.lastIndexOf("."));
            String newFileName = UUID.randomUUID() + fileExtension;
            Path filePath = Paths.get(uploadDir, newFileName);
            Files.copy(file.getInputStream(), filePath, StandardCopyOption.REPLACE_EXISTING);
            return "http://3.37.58.59:8080/image/senior/" + newFileName;
        } catch (IOException e) {
            log.info(e.getMessage());
            throw new AppException(AppErrorCode.CANNOT_SAVE_IMAGES);
        }
    }

    private String createFileName(MultipartFile file) {
        String originalFileName = file.getOriginalFilename();
        String fileExtension = originalFileName.substring(originalFileName.lastIndexOf("."));
        return UUID.randomUUID() + fileExtension;
    }

    private void saveFileData(Senior senior, String filePath, String location) {
        SeniorImage seniorImage = SeniorImage.create(filePath, Location.toLocation(location.trim()), senior);
        log.info(seniorImage.getImage());
        seniorImageRepository.save(seniorImage);
    }

    @Transactional
    public void updateRank(Senior senior, Integer rank) {
        senior.updateRank(rank);
    }

    @Transactional(readOnly = true)
    public List<ReadSeniorImageDTO> readSeniorImages(Senior senior) {
        List<SeniorImage> images = seniorImageRepository.findAllBySenior(senior);
        return images.stream()
                .map(image -> ReadSeniorImageDTO.create(image.getLocation(), image.getImage()))
                .toList();
    }
}
