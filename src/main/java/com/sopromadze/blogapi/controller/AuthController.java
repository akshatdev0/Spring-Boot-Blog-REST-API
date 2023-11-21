package com.sopromadze.blogapi.controller;

import com.sopromadze.blogapi.exception.AppException;
import com.sopromadze.blogapi.exception.BlogapiException;
import com.sopromadze.blogapi.model.role.Role;
import com.sopromadze.blogapi.model.role.RoleName;
import com.sopromadze.blogapi.model.user.User;
import com.sopromadze.blogapi.payload.ApiResponse;
import com.sopromadze.blogapi.payload.JwtAuthenticationResponse;
import com.sopromadze.blogapi.payload.LoginRequest;
import com.sopromadze.blogapi.payload.SignUpRequest;
import com.sopromadze.blogapi.repository.RoleRepository;
import com.sopromadze.blogapi.repository.UserRepository;
import com.sopromadze.blogapi.security.JwtTokenProvider;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Scope;
import io.opentelemetry.semconv.SemanticAttributes;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.validation.Valid;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
	private static final String USER_ROLE_NOT_SET = "User role not set";

	private final AuthenticationManager authenticationManager;

	private final UserRepository userRepository;

	private final RoleRepository roleRepository;

	private final PasswordEncoder passwordEncoder;

	private final JwtTokenProvider jwtTokenProvider;

	private final Tracer tracer;

	@Autowired
	AuthController(AuthenticationManager authenticationManager,
				   UserRepository userRepository,
				   RoleRepository roleRepository,
				   PasswordEncoder passwordEncoder,
				   JwtTokenProvider jwtTokenProvider,
				   OpenTelemetry openTelemetry) {
		this.authenticationManager = authenticationManager;
		this.userRepository = userRepository;
		this.roleRepository = roleRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtTokenProvider = jwtTokenProvider;
		this.tracer = openTelemetry.getTracer(AuthController.class.getName(), "0.0.1");
	}

	@PostMapping("/signin")
	public ResponseEntity<JwtAuthenticationResponse> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsernameOrEmail(), loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);

		String jwt = jwtTokenProvider.generateToken(authentication);
		return ResponseEntity.ok(new JwtAuthenticationResponse(jwt));
	}

	@PostMapping("/signup")
	public ResponseEntity<ApiResponse> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
		Span span = tracer.spanBuilder("/api/auth/signup").setSpanKind(SpanKind.CLIENT).startSpan();
		span.setAttribute(SemanticAttributes.HTTP_REQUEST_METHOD, "POST");

		// Make the span the current span
		try (Scope scope = span.makeCurrent()) {
			if (Boolean.TRUE.equals(userRepository.existsByUsername(signUpRequest.getUsername()))) {
				throw new BlogapiException(HttpStatus.BAD_REQUEST, "Username is already taken");
			}

			if (Boolean.TRUE.equals(userRepository.existsByEmail(signUpRequest.getEmail()))) {
				throw new BlogapiException(HttpStatus.BAD_REQUEST, "Email is already taken");
			}

			String firstName = signUpRequest.getFirstName().toLowerCase();

			String lastName = signUpRequest.getLastName().toLowerCase();

			String username = signUpRequest.getUsername().toLowerCase();

			String email = signUpRequest.getEmail().toLowerCase();

			String password = passwordEncoder.encode(signUpRequest.getPassword());

			User user = new User(firstName, lastName, username, email, password);

			List<Role> roles = new ArrayList<>();

			if (userRepository.count() == 0) {
				roles.add(roleRepository.findByName(RoleName.ROLE_USER)
						.orElseThrow(() -> new AppException(USER_ROLE_NOT_SET)));
				roles.add(roleRepository.findByName(RoleName.ROLE_ADMIN)
						.orElseThrow(() -> new AppException(USER_ROLE_NOT_SET)));
			} else {
				roles.add(roleRepository.findByName(RoleName.ROLE_USER)
						.orElseThrow(() -> new AppException(USER_ROLE_NOT_SET)));
			}

			user.setRoles(roles);

			User result = userRepository.save(user);

			URI location = ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/users/{userId}")
					.buildAndExpand(result.getId()).toUri();

			return ResponseEntity.created(location).body(new ApiResponse(Boolean.TRUE, "User registered successfully"));
		} catch (Throwable t) {
			span.setStatus(StatusCode.ERROR, "Something bad happened!");
			span.recordException(t);
			throw t;
		} finally {
			span.end();
		}
	}
}
