package com.dskim.jwt.config.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.dskim.jwt.model.User;
import com.dskim.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;


// http://localhost:8080/login => 여기서 동작 안함(원래  SecurityConfig에서 formLogin을 썼으면 디폴트 주소로 이 주소에서 동작 
// 그래서 필터를 만들어서 얘를 동작시켜 줘야함 
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {
	
	private final UserRepository userRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User userEntity = userRepository.findByUsername(username);
		return new PrincipalDetails(userEntity);
	}
	
	

}
