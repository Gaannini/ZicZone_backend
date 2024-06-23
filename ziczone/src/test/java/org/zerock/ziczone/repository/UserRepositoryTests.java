package org.zerock.ziczone.repository;

import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.zerock.ziczone.domain.*;

import java.time.LocalDate;

@SpringBootTest
@Log4j2
public class UserRepositoryTests {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PersonalUserRepository personalUserRepository;
    @Autowired
    private CompanyUserRepository companyUserRepository;
    @Autowired
    private PickAndScrapRepository pickAndScrapRepository;
    @Autowired
    private ResumeRepository resumeRepository;
    @Autowired
    private PortfolioRepository portfolioRepository;
    @Autowired
    private CertificateRepository certificateRepository;

    @Test
    public void testPersonalInsert(){
        User user = User.builder()
                .userName("전민재")
                .email("alswo9672@gmail.com")
                .password("1234")
                .userIntro("전민재입니다.")
                .userType(UserType.PERSONAL)
                .build();
        userRepository.save(user);

        PersonalUser personalUser = PersonalUser.builder()
                .career("신입")
                .isPersonalVisible(true)
                .isCompanyVisible(true)
                .gender(Gender.MALE)
                .user(user)
                .build();
        personalUserRepository.save(personalUser);

        log.info("User saved: " + user);
        log.info("PersonalUser saved: " + personalUser);
    }

    @Test
    public void testCompanyInsert(){
        User user = User.builder()
                .userName("토스")
                .email("support@toss.im")
                .password("1234")
                .userIntro("toss입니다.")
                .userType(UserType.COMPANY)
                .build();
        userRepository.save(user);

        LocalDate companyYear = LocalDate.of(2013,8,1);

        CompanyUser companyUser = CompanyUser.builder()
                .companyNum("226-27-20508")
                .companyAddr("서울특별시 강남구 테헤란로 131")
                .companyYear(companyYear)
                .companyLogo("http://toss.png")
                .companyCeo("이승건")
                .user(user)
                .build();
        companyUserRepository.save(companyUser);

        log.info("User saved: " + user);
        log.info("CompanyUser saved: " + companyUser);
    }

    @Test
    public void testPickAndScrapInsert(){
        CompanyUser companyUser = companyUserRepository.findByCompanyId(1L);
        PersonalUser personalUser = personalUserRepository.findByPersonalId(1L);
        PickAndScrap pickAndScrap = PickAndScrap.builder()
                .pick(true)
                .scrap(true)
                .companyUser(companyUser)
                .personalUser(personalUser)
                .build();
        pickAndScrapRepository.save(pickAndScrap);

        log.info("PickAndScrap saved: " + pickAndScrap);
    }
    @Test
    public void testResumeInsert(){
        PersonalUser personalUser = personalUserRepository.findByPersonalId(1L);

        Resume resume = Resume.builder()
                .resumeName("전민재")
                .date("1998년04월06일")
                .phoneNum("010-2427-9672")
                .resumePhoto("http://photo.png")
                .personalState("http://personalState.png")
                .personalUser(personalUser)
                .build();

        resumeRepository.save(resume);
        log.info("Resume saved: " + resume);
    }
    @Test
    public void testPortfolioInsert(){
        Resume resume = resumeRepository.findByResumeId(1L);

        Portfolio portfolio = Portfolio.builder()
                .portFile("http://portfoliofile.png")
                .resume(resume)
                .build();
        portfolioRepository.save(portfolio);
        log.info("Portfolio saved: " + portfolio);

    }
    @Test
    public void testCertificateInsert(){
        Resume resume = resumeRepository.findByResumeId(1L);

        Certificate certificate = Certificate.builder()
                .cert("정보처리기사")
                .certDate("2024-06-23")
                .resume(resume)
                .build();
        certificateRepository.save(certificate);

        log.info("Certificate saved: " + certificate);

    }
}
