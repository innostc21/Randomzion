package com.stc21.boot.auction.service;

import com.stc21.boot.auction.dto.LotDto;
import com.stc21.boot.auction.dto.UserDto;
import com.stc21.boot.auction.entity.Lot;
import com.stc21.boot.auction.entity.Photo;
import com.stc21.boot.auction.entity.Purchase;
import com.stc21.boot.auction.entity.User;
import com.stc21.boot.auction.exception.ConcurrentBuyException;
import com.stc21.boot.auction.exception.NotEnoughMoneyException;
import com.stc21.boot.auction.exception.PageNotFoundException;
import com.stc21.boot.auction.repository.LotRepository;
import com.stc21.boot.auction.repository.PhotoRepository;
import com.stc21.boot.auction.repository.PurchaseRepository;
import com.stc21.boot.auction.repository.UserRepository;
import lombok.SneakyThrows;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.*;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.stream.Collectors;

@Service
public class LotServiceImpl implements LotService {

    private final ModelMapper modelMapper;
    private final LotRepository lotRepository;
    private final PurchaseRepository purchaseRepository;
    private final UserRepository userRepository;
    private final UserService userService;
    private final GoogleDriveService googleDriveService;
    private final PhotoRepository photoRepository;
    public LotServiceImpl(ModelMapper modelMapper,
                          LotRepository lotRepository,
                          PurchaseRepository purchaseRepository,
                          UserRepository userRepository,
                          UserService userService,
                          GoogleDriveService googleDriveService,
                          PhotoRepository photoRepository) {
        this.modelMapper = modelMapper;
        this.lotRepository = lotRepository;
        this.purchaseRepository = purchaseRepository;
        this.userRepository = userRepository;
        this.userService = userService;
        this.googleDriveService = googleDriveService;
        this.photoRepository = photoRepository;
    }

    /* Read functions */
        /* Basic read functions */

    @Override
    public LotDto findById(long id) {
        Optional<Lot> lot = lotRepository.findById(id);
        LotDto lotDto = null;
        if (lot.isPresent())
            lotDto = convertToDto(lot.get());
        return lotDto;
    }

    @Override
    public Page<LotDto> getPaginated(Pageable pageable) {
        PageRequest pageRequest = PageRequest.of(
                pageable.getPageNumber(),
                pageable.getPageSize(),
                pageable.getSortOr(Sort.unsorted()));

        return lotRepository.findAll(pageRequest).map(this::convertToDto);
    }

    @Override
    public Page<LotDto> getPaginated(Lot exampleLot, Pageable pageable) {
        if (exampleLot == null)
            throw new NullPointerException("Example is null");

        ExampleMatcher.GenericPropertyMatcher matcherContains = new ExampleMatcher.GenericPropertyMatcher().contains().ignoreCase();

        ExampleMatcher exampleMatcher = ExampleMatcher.matching()
                .withIgnorePaths("id")
                .withMatcher("name", matcherContains)
                .withMatcher("description", matcherContains);

        Example<Lot> example = Example.of(exampleLot, exampleMatcher);

        Pageable pageRequest = Pageable.unpaged();
        if (pageable.isPaged())
            pageRequest = PageRequest.of(
                    pageable.getPageNumber(),
                    pageable.getPageSize(),
                    pageable.getSortOr(Sort.unsorted()));

        return lotRepository.findAll(example, pageRequest).map(this::convertToDto);
    }

    private Page<LotDto> getBoughtAndPaginated(Boolean isDeleted, boolean isBought, Lot exampleLot, Pageable pageable) {
        if (exampleLot == null)
            exampleLot = new Lot();

        exampleLot.setDeleted(isDeleted);
        exampleLot.setBought(isBought);

        return getPaginated(exampleLot, pageable);
    }

        /* Dependent read functions */

    @Override
    public List<Lot> getUnboughtLots() {
        return lotRepository.findByDeletedFalseAndBoughtFalse();
    }

    @Override
    public Page<LotDto> getUnboughtLots(Lot exampleLot, Pageable pageable) {
        return getBoughtAndPaginated(false,false, exampleLot, pageable);
    }

    @Override
    public Page<LotDto> getBoughtLotsOf(String username, Pageable pageable) {
        Lot exampleLot = new Lot();
        User user = userRepository.findByUsername(username).orElseThrow(() -> new NullPointerException("Not found user with this username"));
        exampleLot.setUser(user);

        return getBoughtAndPaginated(false, true, exampleLot, pageable);
    }

    @Override
    public Page<LotDto> getUnboughtLotsOf(String username, Pageable pageable) {
        Lot exampleLot = new Lot();
        User user = userRepository.findByUsername(username).orElseThrow(() -> new NullPointerException("Not found user with this username"));
        exampleLot.setUser(user);

        return getBoughtAndPaginated(null, false, exampleLot, pageable);
    }

    @Override
    public Page<LotDto> getBoughtLotsBy(String username, Pageable pageable) {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new NullPointerException("Not found user with this username"));

        Page<Purchase> purchasePage = purchaseRepository.findAllByBuyer(user, pageable);

        List<LotDto> lotDtos = purchaseRepository.findAllByBuyer(user, pageable).toList().stream()
                .map(Purchase::getItem)
                .map(this::convertToDto)
                .collect(Collectors.toList());

        Page<LotDto> lotDtoPage = new PageImpl<LotDto>(lotDtos, purchasePage.getPageable(), purchasePage.getTotalElements());

        return lotDtoPage;
    }

    /* Create & update functions */

    @SneakyThrows
    @Override
    public Lot saveNewLot(LotDto lotDto, Authentication token, MultipartFile[] images) {
        UserDto authed = userService.findByUsername(token.getName());
        lotDto.setUserDto(authed);
        LocalDateTime nowDateTime = LocalDateTime.now();
        lotDto.setCreationTime(nowDateTime);
        lotDto.setLastModTime(nowDateTime);

        Lot insertedLot = lotRepository.save(convertToEntity(lotDto));

        if ((images.length == 1) && images[0].getOriginalFilename().equals("")) {
            return lotRepository.getOne(insertedLot.getId());
        }

        List<Photo> uploadPhotos = googleDriveService.uploadLotMedia(insertedLot.getId(), images);
        uploadPhotos.forEach(photo -> {
            photo.setLot(insertedLot);
            photo.setDeleted(false);
            photoRepository.save(photo);
        });
        return lotRepository.getOne(insertedLot.getId());
    }

    /**
     *
     * @param username User.username, which want to buy a lot
     * @param lotDto DTO of lot, which usenrname want to buy
     * @throws NotEnoughMoneyException if User.wallet less than item's cost
     */
    @Override
    @Transactional(propagation = Propagation.REQUIRED
            ,isolation = Isolation.SERIALIZABLE)
    public void sale(String username, LotDto lotDto) throws NotEnoughMoneyException {

        User buyer = userRepository.findByUsername(username).orElseThrow(NullPointerException::new);//userService.findByUsername(username);
        Long amount = lotDto.getCurrentPrice();
        if(buyer.getWallet() < amount) {
            throw new NotEnoughMoneyException("Недостаточно средств на счету");
        }
        User seller = userRepository.findByUsername(lotDto.getUserDto().getUsername()).orElseThrow(NullPointerException::new);//userService.findByUsername(username);
        if (seller.getId() == buyer.getId()) throw new PageNotFoundException();

        Lot boughtLot = lotRepository.findById(lotDto.getId()).orElseThrow(NullPointerException::new);
        boughtLot.setBought(true);
        seller.setWallet(seller.getWallet() + amount);
        buyer.setWallet(buyer.getWallet() - amount);

        Purchase purchase = new Purchase();
        purchase.setBuyer(buyer);
        purchase.setItem(boughtLot);
        purchase.setPurchaseTime(LocalDateTime.now());

        try {
            purchaseRepository.saveAndFlush(purchase);
        } catch (Exception e) {
            throw new ConcurrentBuyException(e.getMessage());
        }
    }

    @Override
    @Transactional
    public void updateAllLots(List<Lot> lots) {
        lots.forEach(lot -> {
            lotRepository.updateCurrentPrice(calcCurrentPrice(lot), lot.getId());
        });
    }

    private Long calcCurrentPrice(Lot lot) {
        Random random = new Random();
        Long max = lot.getMaxPrice();
        Long min = lot.getMinPrice();
        long randomValue = min + random.nextInt((int) (max - min));
        return randomValue;
    }

    @Override
    @Transactional
    public void setDeletedTo(long id, boolean newValue) {
        lotRepository.updateDeletedTo(id, newValue);
    }

    /* Util functions */

    @Override
    public LotDto convertToDto(Lot lot) {
        if (lot == null) return null;

        LotDto lotDto = modelMapper.map(lot, LotDto.class);

        lotDto.setUserDto(userService.convertToDto(lot.getUser()));

        for (Photo photo : lot.getPhotos()) {
            if (false == photo.getDeleted()) {
                lotDto.getPhotoUrls().add(photo.getUrl());
            }
        }

        return lotDto;
    }

    private Lot convertToEntity(LotDto lotDto) {
        return modelMapper.map(lotDto, Lot.class);
    }
}
