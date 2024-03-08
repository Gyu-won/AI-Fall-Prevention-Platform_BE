package happyaging.server.controller.admin;

import happyaging.server.domain.image.ExampleImage;
import happyaging.server.domain.image.Location;
import happyaging.server.domain.image.SeniorImage;
import happyaging.server.domain.option.Option;
import happyaging.server.domain.product.InstalledImage;
import happyaging.server.domain.product.Product;
import happyaging.server.domain.question.Question;
import happyaging.server.domain.senior.Senior;
import happyaging.server.domain.survey.Response;
import happyaging.server.domain.survey.Result;
import happyaging.server.domain.survey.Survey;
import happyaging.server.domain.user.User;
import happyaging.server.domain.user.UserType;
import happyaging.server.dto.admin.image.UpdateExampleImageDTO;
import happyaging.server.dto.admin.product.ProductInfo;
import happyaging.server.dto.admin.product.ReadProductInstallDTO;
import happyaging.server.dto.admin.senior.ReadSeniorDTO;
import happyaging.server.dto.admin.survey.CreateQuestionDTO;
import happyaging.server.dto.admin.survey.ExcelDataDTO;
import happyaging.server.dto.admin.survey.ReadResponseDTO;
import happyaging.server.dto.admin.survey.ReadSurveyDTO;
import happyaging.server.dto.admin.user.CreateManagerDTO;
import happyaging.server.dto.admin.user.ReadManagerDTO;
import happyaging.server.dto.admin.user.ReadUserDTO;
import happyaging.server.dto.admin.util.PagingResponse;
import happyaging.server.dto.admin.util.StatisticDTO;
import happyaging.server.dto.senior.SeniorResponseDTO;
import happyaging.server.exception.AppException;
import happyaging.server.exception.errorcode.AppErrorCode;
import happyaging.server.repository.image.ExampleImageRepository;
import happyaging.server.repository.image.SeniorImageRepository;
import happyaging.server.repository.option.OptionRepository;
import happyaging.server.repository.product.InstalledImageRepository;
import happyaging.server.repository.product.ProductRepository;
import happyaging.server.repository.question.QuestionRepository;
import happyaging.server.repository.senior.SeniorRepository;
import happyaging.server.repository.survey.SurveyRepository;
import happyaging.server.repository.user.UserRepository;
import happyaging.server.service.admin.AdminService;
import happyaging.server.service.auth.AuthService;
import happyaging.server.service.senior.SeniorService;
import happyaging.server.service.survey.ResponseService;
import happyaging.server.service.survey.ResultService;
import happyaging.server.service.survey.SurveyService;
import happyaging.server.service.user.UserService;
import jakarta.validation.Valid;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequiredArgsConstructor
@Slf4j
@RequestMapping("admin")
public class AdminController {

    private final UserService userService;
    private final AuthService authService;
    private final ResultService resultService;
    private final SeniorService seniorService;
    private final SurveyService surveyService;
    private final ResponseService responseService;
    private final AdminService adminService;

    private final UserRepository userRepository;
    private final SeniorRepository seniorRepository;
    private final SurveyRepository surveyRepository;
    private final ProductRepository productRepository;
    private final InstalledImageRepository installedImageRepository;
    private final ExampleImageRepository exampleImageRepository;
    private final SeniorImageRepository seniorImageRepository;
    private final QuestionRepository questionRepository;
    private final OptionRepository optionRepository;
    private final BCryptPasswordEncoder encoder;

    @Value("${file.static-image}")
    private String staticPath;

    @Transactional(readOnly = true)
    @GetMapping("/statistics")
    public StatisticDTO readStatistics() {
        return StatisticDTO.create(userRepository.count(), seniorRepository.count(), surveyRepository.count());
    }

    @Transactional
    @PostMapping("/user/manager")
    public Long createManager(@RequestBody @Valid CreateManagerDTO request) {
        authService.checkDuplicateEmail(request.getEmail());
        User user = User.createManager(request.getEmail(), request.getPassword(), request.getName(),
                request.getPhoneNumber(), encoder);
        userRepository.save(user);
        return user.getId();
    }

    @Transactional
    @DeleteMapping("/user/manager/{managerId}")
    public void deleteManager(@PathVariable Long managerId) {
        userService.deleteUser(managerId);
    }

    @Transactional
    @PutMapping("/user/manager/{managerId}")
    public void updateManager(@RequestBody @Valid CreateManagerDTO dto, @PathVariable Long managerId) {
        userService.updateUserInfo(managerId, dto.getEmail(), dto.getName(), dto.getPhoneNumber(), dto.getPassword());
    }

    @Transactional(readOnly = true)
    @GetMapping("/user/manager")
    public PagingResponse<ReadManagerDTO> readManager(@RequestParam Integer page,
                                                      @RequestParam(required = false) String name) {
        Page<User> pageNumber = userRepository.findAllByNameContainingAndUserTypeOrderByCreatedAtDesc(name,
                UserType.MANAGER, PageRequest.of(page, 20));
        List<ReadManagerDTO> readManagerDTOS = pageNumber.getContent().stream()
                .map(ReadManagerDTO::create)
                .toList();
        return new PagingResponse<>(pageNumber.hasNext(), readManagerDTOS);
    }

    @Transactional(readOnly = true)
    @GetMapping("/user")
    public PagingResponse<ReadUserDTO> readUser(@RequestParam Integer page,
                                                @RequestParam(required = false) String name) {
        Page<User> pageNumber = userRepository.findAllByNameContainingOrderByCreatedAtDesc(name,
                PageRequest.of(page, 20));
        List<ReadUserDTO> readUserDTOS = pageNumber.getContent().stream()
                .map(ReadUserDTO::create)
                .toList();
        return new PagingResponse<>(pageNumber.hasNext(), readUserDTOS);
    }

    @Transactional(readOnly = true)
    @GetMapping("/senior")
    public PagingResponse<ReadSeniorDTO> readSenior(@RequestParam Integer page,
                                                    @RequestParam(required = false) String name) {
        Page<Senior> pageNumber = seniorRepository.findAllByUser_NameContainingAndUser_UserType(name,
                UserType.MANAGER, PageRequest.of(page, 20));
        List<ReadSeniorDTO> readSeniorDTOS = pageNumber.getContent().stream()
                .map(ReadSeniorDTO::create)
                .toList();
        return new PagingResponse<>(pageNumber.hasNext(), readSeniorDTOS);
    }

    @Transactional(readOnly = true)
    @GetMapping("/survey")
    public PagingResponse<ReadSurveyDTO> readSurvey(@RequestParam Integer page,
                                                    @RequestParam(required = false) LocalDate startDate,
                                                    @RequestParam(required = false) LocalDate endDate,
                                                    @RequestParam(required = false) String seniorName,
                                                    @RequestParam(required = false) String seniorAddress,
                                                    @RequestParam(required = false) String userName) {
        Page<Survey> pageNumber;
        if (startDate == null) {
            startDate = LocalDate.of(2024, 1, 1);
        }
        if (endDate == null) {
            endDate = LocalDate.now();
        }
        if (seniorName.isEmpty()) {
            pageNumber = surveyRepository.findAllBySenior_AddressContainingAndSenior_User_NameContainingAndDateBetweenOrderByDateDesc(
                    seniorAddress, userName, startDate, endDate, PageRequest.of(page, 20));
        } else {
            pageNumber = surveyRepository.findAllBySenior_NameAndSenior_AddressContainingAndSenior_User_NameContainingAndDateBetweenOrderByDateDesc(
                    seniorName, seniorAddress, userName, startDate, endDate, PageRequest.of(page, 20));
        }
        List<ReadSurveyDTO> readSurveyDTOS = pageNumber.getContent().stream()
                .map(survey -> {
                    Result result = resultService.findBySurvey(survey);
                    Senior senior = seniorService.findSeniorById(survey.getSenior().getId());
                    return ReadSurveyDTO.create(survey, result, senior);
                })
                .toList();
        return new PagingResponse<>(pageNumber.hasNext(), readSurveyDTOS);
    }

    @Transactional(readOnly = true)
    @GetMapping("/survey/{surveyId}")
    public List<ReadResponseDTO> readResponse(@PathVariable Long surveyId) {
        Survey survey = surveyService.findSurveyById(surveyId);
        List<Response> responses = responseService.findResponsesBySurvey(survey);
        return responses.stream().map(ReadResponseDTO::create)
                .toList();
    }

    @Transactional(readOnly = true)
    @GetMapping("/product")
    public List<ProductInfo> readProducts() {
        List<ProductInfo> productInfos = new ArrayList<>();

        List<Product> products = productRepository.findAll();
        for (Product product : products) {
            List<InstalledImage> installImages = installedImageRepository.findAllByProductId(product.getId());
            productInfos.add(ProductInfo.create(product, installImages));
        }
        return productInfos;
    }

    @Transactional
    @PostMapping("/install/{productId}")
    public ResponseEntity<Object> addInstallImage(@RequestParam("imageFiles") MultipartFile[] images,
                                                  @PathVariable Long productId) {
        Product product = productRepository.findById(productId)
                .orElseThrow(() -> new AppException(AppErrorCode.INVALID_PRODUCT));
        List<String> filePaths = uploadFiles(images, "/install");
        List<InstalledImage> installedImages = filePaths.stream()
                .map(image -> InstalledImage.create(image, product))
                .toList();
        installedImageRepository.saveAll(installedImages);
        return ResponseEntity.ok().build();
    }

    @Transactional(readOnly = true)
    @GetMapping("/install/{productId}")
    public List<ReadProductInstallDTO> readInstallImage(@PathVariable Long productId) {
        List<InstalledImage> images = installedImageRepository.findAllByProductId(productId);
        return images.stream()
                .map(ReadProductInstallDTO::create)
                .toList();
    }

    @Transactional
    @DeleteMapping("/install/{installId}")
    public ResponseEntity<Object> deleteInstallImage(@PathVariable Long installId) {
        InstalledImage image = installedImageRepository.findById(installId)
                .orElseThrow(() -> new AppException(AppErrorCode.INVALID_INSTALL_IMAGE));
        installedImageRepository.delete(image);
        return ResponseEntity.ok().build();
    }

    @Transactional
    @PutMapping("/image")
    public ResponseEntity<Object> updateInstallImageInfo(@RequestBody UpdateExampleImageDTO dto) {
        List<String> descriptions = dto.getDescription();

        List<ExampleImage> images = exampleImageRepository.findAllByLocation(dto.getLocation());
        for (int i = 0; i < images.size(); i++) {
            images.get(i).updateInfo(descriptions.get(i));
        }

        return ResponseEntity.ok().build();
    }

    @Transactional
    @PutMapping("/image/{location}")
    public ResponseEntity<Object> updateInstallImage(@PathVariable Location location,
                                                     @RequestParam("imageFiles") MultipartFile[] imageFiles) {
        List<ExampleImage> images = exampleImageRepository.findAllByLocation(location);
        List<String> filePaths = uploadFiles(imageFiles, "/example");
        for (int i = 0; i < images.size(); i++) {
            images.get(i).updateImage(filePaths.get(i));
        }

        return ResponseEntity.ok().build();
    }

    @Transactional(readOnly = true)
    @GetMapping("/senior/image")
    public List<SeniorResponseDTO> readSeniorWithImage() {
        List<Senior> seniors = seniorImageRepository.findAllSeniorsWithImages();
        return seniors.stream()
                .map(SeniorResponseDTO::create)
                .toList();
    }

    @Transactional(readOnly = true)
    @GetMapping("/senior/image/{seniorId}")
    public ResponseEntity<Resource> readSeniorImages(@PathVariable Long seniorId) {
        Senior senior = seniorService.findSeniorById(seniorId);
        List<SeniorImage> images = seniorImageRepository.findAllBySenior(senior);
        try {
            Path zipFilePath = createZipFileWithImages(images);
            Resource resource = new UrlResource(zipFilePath.toUri());
            zipFilePath.toFile().deleteOnExit();

            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType("application/zip"))
                    .header("Content-Disposition", "attachment; filename=\"images.zip\"")
                    .body(resource);
        } catch (IOException exception) {
            throw new AppException(AppErrorCode.INVALID_FILE);
        }
    }

    @Transactional
    @PostMapping("/survey")
    public ResponseEntity<Object> createQuestion(@RequestBody @Valid CreateQuestionDTO dto) {
        String number = checkValidNumber(dto.getNumber());
        Question question = Question.create(number, dto.getContent(), dto.getQuestionType(),
                dto.getResponseType());
        questionRepository.save(question);
        if (dto.getOptions() != null) {
            List<Option> options = dto.getOptions().stream()
                    .map(option -> Option.create(option.getContent(), question))
                    .toList();
            optionRepository.saveAll(options);
        }
        return ResponseEntity.ok().build();
    }

    @Transactional
    @DeleteMapping("survey/{questionId}")
    public ResponseEntity<Object> deleteQuestion(@PathVariable Long questionId) {
        Question question = questionRepository.findById(questionId)
                .orElseThrow(() -> new AppException(AppErrorCode.INVALID_QUESTION));
        checkValidNumber(question.getNumber());
        question.delete();
        return ResponseEntity.ok().build();
    }

    @GetMapping("/data")
    public ResponseEntity<Resource> exportToExcel() {
        List<ExcelDataDTO> data = surveyService.readAllData();
        byte[] excelFile = adminService.createExcelFile(data);
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/vnd.ms-excel"))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=survey_data.xlsx")
                .body(new ByteArrayResource(excelFile));
    }

    private String checkValidNumber(String number) {
        String[] numbers = number.split("-");
        int numberValue = Integer.parseInt(numbers[0]);
        if (numberValue < 15 && numberValue > 0) {
            throw new AppException(AppErrorCode.INVALID_QUESTION_NUMBER);
        }
        return numbers[0];
    }

    private Path createZipFileWithImages(List<SeniorImage> images) throws IOException {
        Path zipFilePath = Files.createTempFile("images-", ".zip");
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(zipFilePath.toFile()))) {
            for (SeniorImage image : images) {
                Path path = Paths.get(image.getImage());
                if (Files.exists(path) && !Files.isDirectory(path)) {
                    ZipEntry zipEntry = new ZipEntry(path.getFileName().toString());
                    zos.putNextEntry(zipEntry);
                    Files.copy(path, zos);
                    zos.closeEntry();
                }
            }
        }
        return zipFilePath;
    }


    private List<String> uploadFiles(MultipartFile[] images, String imagePath) {
        List<String> filePaths = new ArrayList<>();
        String path = staticPath + imagePath;
        try {
            for (MultipartFile image : images) {
                String originalFilename = image.getOriginalFilename();
                String fileExtension = originalFilename.substring(originalFilename.lastIndexOf("."));
                String newFileName = UUID.randomUUID() + fileExtension;
                Path filePath = Paths.get(path, newFileName);
                Files.copy(image.getInputStream(), filePath, StandardCopyOption.REPLACE_EXISTING);
                filePaths.add("http://3.37.58.59:8080/image" + imagePath + "/" + newFileName);
            }
            return filePaths;
        } catch (IOException exception) {
            throw new AppException(AppErrorCode.CANNOT_SAVE_IMAGES);
        }
    }
}
